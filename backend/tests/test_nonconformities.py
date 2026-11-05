"""Задача 3.4: несоответствия, план устранения, «Отправить в Устранение», события vm."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from app.api.nonconformities import signature
from app.db.models import AssessedObject, AuditRecord, Evidence, InboxEvent, Nonconformity
from app.domain import nonconformities as rules
from app.integrations.vm.client import LiveVmClient, Ticket, VmError, get_vm_client
from tests.test_demo import demo_env  # noqa: F401 — фикстура

SECRET = "s" * 40


def _plan(client, oid, h):
    r = client.get(f"/objects/{oid}/nonconformities", headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def _by_ref(plan):
    return {i["ref"]: i for i in plan["items"]}


# ---------- Домен ----------


def test_state_and_overdue():
    assert rules.state(None, None, None) == "open"
    assert rules.state(None, "7", "new") == "in_work"
    assert rules.state(None, "7", "fixed") == "fixed"
    assert rules.state(None, "7", "verified") == "verified"
    assert rules.state(None, "7", "risk_accepted") == "decision"
    assert rules.state(datetime.now(UTC), "7", "verified") == "closed"
    now = datetime(2026, 11, 5, tzinfo=UTC)
    past = now - timedelta(hours=1)
    assert rules.overdue(kind="vuln", st="in_work", deadline_at=past, due_date=None, now=now)
    # Подтверждённое устранение и закрытый пункт не просрочены.
    assert not rules.overdue(kind="vuln", st="verified", deadline_at=past, due_date=None, now=now)
    assert not rules.overdue(kind="vuln", st="closed", deadline_at=past, due_date=None, now=now)
    # Мера без срока не просрочена (п. 9 ТЗ: сроки необязательны).
    assert not rules.overdue(kind="measure", st="open", deadline_at=None, due_date=None, now=now)
    assert rules.overdue(
        kind="measure", st="open", deadline_at=None, due_date=now.date() - timedelta(1), now=now
    )


def test_check_remediation():
    known = {"CM1", "CM2"}
    r = rules.check_remediation("update", "foreign", None, ["CM1"], known)
    # Компенсирующие меры при обновлении сбрасываются; тестирование не отмечено → False.
    assert r == rules.Remediation("update", "foreign", False, [])
    r = rules.check_remediation("update", "domestic", True, [], known)
    assert r.update_tested is None  # для российского ПО п. 23 не требует отметки
    r = rules.check_remediation("compensating", "foreign", True, ["CM2", "CM2", "CM1"], known)
    assert r == rules.Remediation("compensating", None, None, ["CM2", "CM1"])
    with pytest.raises(rules.PlanError, match=r"перечне п\. 25"):
        rules.check_remediation("compensating", None, None, ["CM9"], known)
    with pytest.raises(rules.PlanError, match="хотя бы одну"):
        rules.check_remediation("compensating", None, None, [], known)
    with pytest.raises(rules.PlanError):
        rules.check_remediation("patch", None, None, [], known)
    w = rules.warnings(
        kind="vuln",
        st="in_work",
        method="update",
        update_origin="opensource",
        update_tested=False,
        resend=True,
        assessed=True,
    )
    assert any("п. 23" in x for x in w) and any("отправьте повторно" in x for x in w)


def test_live_client_contract():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.method == "POST" and req.url.path == "/projects/p1/external-tickets":
            return httpx.Response(201, json={"id": 42, "status": "new"})
        if req.url.path == "/tickets/42":
            return httpx.Response(200, json={"id": 42, "status": "in_progress"})
        if req.url.path == "/tickets/43":
            return httpx.Response(404, json={"detail": "нет"})
        return httpx.Response(404, json={"detail": "Not Found"})

    from app.core.config import Settings

    s = Settings(vm_mode="live", vm_url="http://vm:8000/", vm_token="tok")  # noqa: S106
    c = LiveVmClient(s, transport=httpx.MockTransport(handler))
    assert c.upsert_ticket("p1", {"external_id": "x"}) == Ticket("42", "new")
    assert seen[0].headers["authorization"] == "Bearer tok"
    assert json.loads(seen[0].content) == {"external_id": "x"}
    assert c.ticket("42") == Ticket("42", "in_progress")
    assert c.ticket("43") is None
    with pytest.raises(VmError, match="нет проекта p2") as e:
        c.upsert_ticket("p2", {"external_id": "x"})
    assert e.value.code == "vm_not_found"
    with pytest.raises(VmError, match="GRC_VM_URL"):
        LiveVmClient(Settings(vm_mode="live")).upsert_ticket("p1", {})


# ---------- План по демо ----------


def test_plan_from_measures_and_vulns(client, demo_env):  # noqa: F811
    r, h = demo_env
    plan = _plan(client, r.object_id, h["demo-viewer"])
    items = plan["items"]
    assert plan["vm"]["project_id"] == "vm-demo-gis" and plan["vm"]["mode"] == "fixture"
    assert [c["code"] for c in plan["compensating_measures"]] == [
        "CM1",
        "CM2",
        "CM3",
        "CM4",
        "CM5",
    ]
    measures = [i for i in items if i["kind"] == "measure"]
    vulns = [i for i in items if i["kind"] == "vuln"]
    assert measures and vulns
    assert {i["source_status"] for i in measures} <= {"not_implemented", "partial"}
    # Срок уязвимости — из оценки по п. 21; у неоценённой — запрет на отправку.
    by = _by_ref(plan)
    ssh = by["BDU:2024-04835"]
    assert ssh["level"] and ssh["deadline_at"] and ssh["v"]
    unassessed = [i for i in vulns if not i["level"]]
    assert unassessed and "оцените уязвимость" in unassessed[0]["send_blocker"]
    # Организационная мера не уходит заявкой.
    manual = [i for i in measures if i["measure_method"] == "manual"]
    assert manual and all("документами" in i["send_blocker"] for i in manual)
    # Порядок: меры по приоритету, затем уязвимости по уровню.
    kinds = [i["kind"] for i in items if i["state"] != "closed"]
    assert kinds == sorted(kinds, key=lambda k: k != "measure")
    assert plan["counts"]["total"] == len(measures) + len(vulns)


def test_demo_tickets_and_events(client, session, demo_env):  # noqa: F811
    r, h = demo_env
    plan = _plan(client, r.object_id, h["demo-viewer"])
    by = _by_ref(plan)
    ssh, log4j = by["BDU:2024-04835"], by["BDU:2021-06061"]
    assert ssh["vm_ticket_id"] and ssh["state"] == "in_work" and ssh["vm_status"] == "in_progress"
    assert ssh["method"] == "update" and ssh["update_tested"] is True and not ssh["warnings"]
    assert log4j["state"] == "decision" and log4j["compensating"] == ["CM2", "CM4"]
    assert any("без исправления" in w for w in log4j["warnings"])
    verified = [i for i in plan["items"] if i["state"] == "verified"]
    assert len(verified) == 1 and verified[0]["kind"] == "measure"
    m = verified[0]
    assert m["vm_verified_result"] == "verified" and m["vm_verified_run_id"] == "8"
    ev = session.scalars(
        select(Evidence).where(
            Evidence.object_measure_id == uuid.UUID(m["object_measure_id"]),
            Evidence.kind == "remediation",
        )
    ).all()
    assert len(ev) == 1 and "подтверждено" in ev[0].summary
    # Доказательство видно в шторке меры.
    lst = client.get(
        f"/object-measures/{m['object_measure_id']}/evidence", headers=h["demo-viewer"]
    ).json()
    assert any(e["kind"] == "remediation" for e in lst)
    d = client.get(f"/nonconformities/{m['id']}", headers=h["demo-viewer"]).json()
    kinds = [e["kind"] for e in d["history"]]
    assert kinds[0] == "vm_verified" and "sent" in kinds and kinds[-1] == "opened"
    one = client.get(
        f"/object-measures/{m['object_measure_id']}/nonconformity", headers=h["demo-viewer"]
    ).json()
    assert one["id"] == m["id"]


def test_patch_rules_and_rights(client, demo_env):  # noqa: F811
    r, h = demo_env
    exp, viewer = h["demo-exp"], h["demo-viewer"]
    plan = _plan(client, r.object_id, exp)
    by = _by_ref(plan)
    vid = by["BDU:2024-04835"]["id"]
    mid = next(i["id"] for i in plan["items"] if i["kind"] == "measure")
    url = f"/nonconformities/{vid}"
    assert client.patch(url, headers=viewer, json={"comment": "x"}).status_code == 403
    bad = client.patch(url, headers=exp, json={"method": "compensating", "compensating": ["CM9"]})
    assert bad.status_code == 422 and "п. 25" in bad.json()["detail"]
    r2 = client.patch(url, headers=exp, json={"due_date": "2026-12-01"})
    assert r2.status_code == 422 and "п. 21" in r2.json()["detail"]
    r3 = client.patch(f"/nonconformities/{mid}", headers=exp, json={"method": "update"})
    assert r3.status_code == 422
    ok = client.patch(
        f"/nonconformities/{mid}",
        headers=exp,
        json={"due_date": "2026-12-01", "priority": "low", "action": "  Настроить  "},
    )
    assert ok.status_code == 200, ok.text
    d = ok.json()
    assert d["due_date"] == "2026-12-01" and d["action"] == "Настроить"
    assert d["history"][0]["kind"] == "edited" and "срок" in d["history"][0]["text"]
    # Смена способа у отправленной уязвимости — «отправьте повторно».
    d = client.patch(
        url, headers=exp, json={"method": "compensating", "compensating": ["CM1"]}
    ).json()
    assert d["resend"] is True
    again = client.post(f"/nonconformities/{vid}/send", headers=exp)
    assert again.status_code == 200 and again.json()["resend"] is False
    assert again.json()["vm_ticket_id"] == by["BDU:2024-04835"]["vm_ticket_id"]
    assert again.json()["history"][0]["text"].startswith("Отправлено повторно")


def test_send_errors(client, session, demo_env):  # noqa: F811
    r, h = demo_env
    exp = h["demo-exp"]
    plan = _plan(client, r.object_id, exp)
    blocked = next(i for i in plan["items"] if i["send_blocker"])
    ready = next(i for i in plan["items"] if i["state"] == "open" and not i["send_blocker"])
    out = client.post(
        f"/objects/{r.object_id}/nonconformities/send",
        headers=exp,
        json={"ids": [blocked["id"], str(uuid.uuid4())]},
    ).json()
    assert out["sent"] == 0 and [x["ok"] for x in out["results"]] == [False, False]
    assert client.post(f"/nonconformities/{blocked['id']}/send", headers=exp).status_code == 409

    class Down:
        mode, source = "live", "http://vm"

        def upsert_ticket(self, *a):
            raise VmError("Нет связи с «Устранением» (ConnectError)")

        def ticket(self, tid):
            raise VmError("Нет связи с «Устранением» (ConnectError)")

    client.app.dependency_overrides[get_vm_client] = Down
    try:
        res = client.post(f"/nonconformities/{ready['id']}/send", headers=exp)
        assert res.status_code == 502 and "Нет связи" in res.json()["detail"]
        ref = client.post(f"/objects/{r.object_id}/nonconformities/vm-refresh", headers=exp)
        assert ref.json()["errors"]
    finally:
        client.app.dependency_overrides.pop(get_vm_client, None)
    rec = session.scalars(
        select(AuditRecord).where(
            AuditRecord.action == "nonconformity.send", AuditRecord.result == "error"
        )
    ).first()
    assert rec is not None and rec.details["code"] == "vm_unavailable"


def test_vm_refresh_polls_statuses(client, demo_env):  # noqa: F811
    r, h = demo_env
    exp = h["demo-exp"]

    class Polled:
        mode, source = "live", "http://vm"

        def upsert_ticket(self, *a):
            raise AssertionError

        def ticket(self, tid):
            return Ticket(tid, "fixed")

    client.app.dependency_overrides[get_vm_client] = Polled
    try:
        out = client.post(f"/objects/{r.object_id}/nonconformities/vm-refresh", headers=exp).json()
    finally:
        client.app.dependency_overrides.pop(get_vm_client, None)
    assert out["checked"] == 3 and out["changed"] == 3 and not out["errors"]
    ssh = _by_ref(_plan(client, r.object_id, exp))["BDU:2024-04835"]
    assert ssh["state"] == "fixed"


def test_events_endpoint(client, session, demo_env, monkeypatch):  # noqa: F811
    from app.core.config import get_settings

    r, h = demo_env
    ssh = _by_ref(_plan(client, r.object_id, h["demo-exp"]))["BDU:2024-04835"]
    tid = int(ssh["vm_ticket_id"])

    def env(eid, etype, data, at=None):
        return json.dumps(
            {
                "id": eid,
                "type": etype,
                "source": "vm",
                "time": (at or datetime.now(UTC)).isoformat(),
                "project_id": "vm-demo-gis",
                "subject": f"ticket/{tid}",
                "data": {"ticket_id": tid, **data},
            }
        ).encode()

    body = env("e1", "vm.ticket.status_changed", {"from": "in_progress", "to": "fixed"})
    assert client.post("/events", content=body).status_code == 503  # секрет не задан
    monkeypatch.setenv("GRC_EVENTS_SECRET", SECRET)
    get_settings.cache_clear()
    bad = client.post("/events", content=body, headers={"X-Signature": "sha256=00"})
    assert bad.status_code == 401

    def post(b):
        return client.post("/events", content=b, headers={"X-Signature": signature(SECRET, b)})

    assert post(body).json() == {"status": "applied"}
    assert post(body).json() == {"status": "duplicate"}
    # Опоздавшее событие со старым временем статус не откатывает.
    old = env(
        "e2",
        "vm.ticket.status_changed",
        {"from": "new", "to": "in_progress"},
        at=datetime.now(UTC) - timedelta(days=1),
    )
    assert post(old).json() == {"status": "stale"}
    assert _by_ref(_plan(client, r.object_id, h["demo-exp"]))["BDU:2024-04835"]["state"] == "fixed"
    ver = env("e3", "vm.remediation.verified", {"run_id": 5, "result": "verified"})
    assert post(ver).json() == {"status": "applied"}
    unknown = json.dumps(
        {"id": "e4", "type": "vm.ticket.status_changed", "data": {"ticket_id": 1, "to": "fixed"}}
    ).encode()
    assert post(unknown).json() == {"status": "unknown_ticket"}
    other = json.dumps({"id": "e5", "type": "scanner.run.finished", "data": {}}).encode()
    assert post(other).json() == {"status": "ignored"}
    assert post(b"not json").status_code == 422
    assert session.get(InboxEvent, "e1").result == "applied"
    item = session.get(Nonconformity, uuid.UUID(ssh["id"]))
    session.refresh(item)
    assert item.vm_verified_result == "verified"
    # По уязвимости доказательство мере не добавляется.
    assert not session.scalars(
        select(Evidence).where(Evidence.data["nonconformity_id"].as_string() == ssh["id"])
    ).all()


def test_close_and_reopen_with_measure_status(client, session, demo_env):  # noqa: F811
    r, h = demo_env
    exp = h["demo-exp"]
    plan = _plan(client, r.object_id, exp)
    plain = {
        x["id"]
        for x in client.get(f"/objects/{r.object_id}/measures", headers=exp).json()
        if x["adaptation"] == "none"
    }
    m = next(
        i
        for i in plan["items"]
        if i["kind"] == "measure" and i["state"] == "open" and i["object_measure_id"] in plain
    )
    url = f"/object-measures/{m['object_measure_id']}"
    assert client.patch(url, headers=exp, json={"status": "implemented"}).status_code == 200
    closed = next(i for i in _plan(client, r.object_id, exp)["items"] if i["id"] == m["id"])
    assert closed["state"] == "closed" and "Реализована" in closed["close_reason"]
    assert not closed["overdue"] and closed["send_blocker"] == "Пункт закрыт"
    assert (
        client.patch(f"/nonconformities/{m['id']}", headers=exp, json={"comment": "x"}).status_code
        == 409
    )
    assert client.patch(url, headers=exp, json={"status": "not_implemented"}).status_code == 200
    back = next(i for i in _plan(client, r.object_id, exp)["items"] if i["id"] == m["id"])
    assert back["state"] == "open"
    hist = client.get(f"/nonconformities/{m['id']}", headers=exp).json()["history"]
    assert [e["kind"] for e in hist[:2]] == ["reopened", "closed"]


def test_send_needs_vm_project(client, session, demo_env):  # noqa: F811
    r, h = demo_env
    obj = session.get(AssessedObject, uuid.UUID(r.object_id))
    from app.db.models import Project

    p = session.get(Project, obj.project_id)
    p.vm_project_id = None
    session.commit()
    plan = _plan(client, r.object_id, h["demo-exp"])
    assert plan["vm"]["project_id"] is None
    ready = next(i for i in plan["items"] if i["state"] == "open" and not i["send_blocker"])
    res = client.post(f"/nonconformities/{ready['id']}/send", headers=h["demo-exp"])
    assert res.status_code == 409 and "проект в «Устранении»" in res.json()["detail"]


def test_plan_in_documents(client, session, demo_env):  # noqa: F811
    from app.docs_gen.context import build

    r, _ = demo_env
    obj = session.get(AssessedObject, uuid.UUID(r.object_id))
    ctx = build(session, obj)
    ssh = next(v for v in ctx["vuln_plan"] if v["ref"] == "BDU:2024-04835")
    assert ssh["responsible"].startswith("Петров")
    assert "протестировано по Методике" in ssh["method_title"]
    assert ssh["ticket"].startswith("№") and "В работе" in ssh["ticket"]
    assert ssh["action"].startswith("Обновить OpenSSH")
    assert "vuln_id" not in ssh
    log4j = next(v for v in ctx["vuln_plan"] if v["ref"] == "BDU:2021-06061")
    assert "Компенсирующие меры (п. 25)" in log4j["method_title"]
    assert all("responsible" in n for n in ctx["nonconformities"])
