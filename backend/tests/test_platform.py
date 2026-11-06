"""Режим «Платформы» (задача 3.5): токены по векторам, теневые записи, события, outbox."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from datetime import timedelta
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

VEC = Path(__file__).resolve().parents[2] / "docs" / "integration" / "vectors"
JWT_VEC = json.loads((VEC / "jwt.json").read_text(encoding="utf-8"))
HMAC_VEC = json.loads((VEC / "hmac.json").read_text(encoding="utf-8"))
JWKS = json.loads((VEC / "jwks.json").read_text(encoding="utf-8"))
SEEDS = json.loads((VEC / "signing-keys.TEST-ONLY.json").read_text(encoding="utf-8"))["keys"]
PROJECT_A = JWT_VEC["projects"]["A"]
PROJECT_B = JWT_VEC["projects"]["B"]
SECRET = "test-grc-events-secret"  # noqa: S105 — тестовый секрет
EVENTS_URL = "http://platform-api:8000/events"


class FakePlatform:
    """GET /projects/{id} платформы: проекты A и B векторов."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.projects = {
            PROJECT_A: {
                "id": PROJECT_A,
                "name": "Аудит ООО «Ромашка», 2026",
                "client": "ООО «Ромашка»",
                "contract_ref": "Д-17/2026",
                "period_from": "2026-10-01",
                "period_to": "2026-12-31",
                "status": "active",
            },
            PROJECT_B: {
                "id": PROJECT_B,
                "name": "Аттестация ГИС «Учёт»",
                "client": "Минцифры края",
                "contract_ref": None,
                "period_from": None,
                "period_to": None,
                "status": "active",
            },
        }

    def fetch_project(self, project_id: str, token: str):
        self.calls.append((project_id, token))
        return self.projects.get(project_id)


def _key(kid: str) -> Ed25519PrivateKey:
    seed = next(k["seed_b64url"] for k in SEEDS if k["kid"] == kid)
    return Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(seed + "=="))


def make_token(
    roles: list[str],
    projects: list[str] | None = None,
    sub: str | None = None,
    name: str = "Петров П. П.",
    username: str = "petrov",
    kid: str = "20261104-vec00001",
    typ: str = "user",
) -> str:
    now = int(time.time())
    claims = {
        "iss": "platform",
        "sub": sub or str(uuid.uuid4()),
        "typ": typ,
        "aud": ["scanner", "vm", "grc", "platform"],
        "preferred_username": username,
        "name": name,
        "products": {"grc": roles},
        "projects": projects if projects is not None else [PROJECT_A],
        "iat": now,
        "exp": now + 900,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, _key(kid), algorithm="EdDSA", headers={"kid": kid})


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def platform(db_url, monkeypatch):
    from app.core.config import get_settings
    from app.integrations.platform import client as pclient
    from app.integrations.platform.tokens import JwksCache
    from app.main import create_app

    monkeypatch.setenv("AUTH_MODE", "platform")
    monkeypatch.setenv("PLATFORM_EVENTS_URL", EVENTS_URL)
    monkeypatch.setenv("PLATFORM_EVENTS_SECRET", SECRET)
    monkeypatch.setenv("GRC_OUTBOX_WORKER", "0")
    get_settings.cache_clear()
    fake = FakePlatform()
    pclient.set_client(fake)
    app = create_app()
    fetches: list[int] = []

    def fetch():
        fetches.append(1)
        return JWKS

    app.state.jwks = JwksCache("", fetch=fetch)
    client = TestClient(app)
    client.fake = fake  # type: ignore[attr-defined]
    client.jwks_fetches = fetches  # type: ignore[attr-defined]
    yield client
    pclient.set_client(None)
    get_settings.cache_clear()


# ---------- Векторы платформы ----------


@pytest.mark.parametrize("case", JWT_VEC["cases"], ids=[c["name"] for c in JWT_VEC["cases"]])
def test_platform_jwt_vectors(platform, case):
    for check in (c for c in case["checks"] if c["product"] == "grc"):
        project = check.get("project", PROJECT_A)
        r = platform.get(f"/summary?project={project}", headers=auth(case["token"]))
        assert r.status_code == check["status"], (case["name"], r.text)
        if "detail" in check:
            assert r.json()["detail"] == check["detail"]
        if r.status_code == 401:
            assert r.headers["www-authenticate"] == "Bearer"
        if check["status"] == 200:
            me = platform.get("/me", headers=auth(case["token"])).json()
            assert me["roles"] == check["roles"]
            assert me["auth_mode"] == "platform"


@pytest.mark.parametrize("case", HMAC_VEC["cases"], ids=[c["name"] for c in HMAC_VEC["cases"]])
def test_hmac_vectors(case):
    from app.platform_events import sign

    got = sign(case["secret"], case["body"].encode("utf-8"))
    assert (got == case["headers"].get("X-Signature")) is case["valid"]


def test_hmac_vectors_on_webhook(platform):
    """Подписчик проверяет подпись от байтов тела как есть (вектор platform_to_subscriber)."""
    case = next(c for c in HMAC_VEC["cases"] if c["name"] == "platform_to_subscriber")
    body = case["body"].encode("utf-8")
    good = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    r = platform.post("/events/platform", content=body, headers={"X-Signature": good})
    assert r.status_code == 200
    again = platform.post("/events/platform", content=body, headers={"X-Signature": good})
    assert again.json() == {"status": "duplicate"}
    bad = platform.post(
        "/events/platform", content=body, headers={"X-Signature": case["headers"]["X-Signature"]}
    )
    assert bad.status_code == 401  # подписано чужим секретом


def test_no_token_is_401(platform):
    r = platform.get(f"/summary?project={PROJECT_A}")
    assert r.status_code == 401
    assert r.json()["detail"] == "not_authenticated"
    # Манифест и проверки живости — без токена.
    assert platform.get("/manifest").status_code == 200
    assert platform.get("/health/ready").status_code == 200


# ---------- Теневые записи ----------


def test_shadow_user_created_once_and_renamed(platform, session):
    from app.db.models import AuditRecord, User

    sub = str(uuid.uuid4())
    t1 = make_token(["assessor"], sub=sub, name="Петров П.")
    assert platform.get("/me", headers=auth(t1)).status_code == 200
    t2 = make_token(["assessor", "approve"], sub=sub, name="Петров П. П.")
    me = platform.get("/me", headers=auth(t2)).json()
    assert me["display_name"] == "Петров П. П."
    assert sorted(me["roles"]) == ["approve", "assessor"]
    users = session.scalars(select(User).where(User.platform_sub == sub)).all()
    assert len(users) == 1
    u = users[0]
    assert u.password_hash is None
    assert u.role_rows == []  # роли не хранятся: источник истины — токен
    assert u.platform_roles == ["approve", "assessor"]
    created = session.scalars(
        select(AuditRecord).where(AuditRecord.action == "user.shadow_create")
    ).all()
    assert len(created) == 1


def test_shadow_username_never_takes_local_login(platform, make_user, session):
    from app.db.models import User

    make_user("petrov", "assessor")
    sub = str(uuid.uuid4())
    platform.get("/me", headers=auth(make_token(["viewer"], sub=sub, username="petrov")))
    shadow = session.scalar(select(User).where(User.platform_sub == sub))
    assert shadow.username != "petrov"
    assert shadow.username.startswith("petrov~")


def test_service_token_marked(platform, session):
    from app.db.models import User

    tok = make_token(["viewer"], sub="svc:" + str(uuid.uuid4()), typ="service", projects=["*"])
    me = platform.get("/me", headers=auth(tok)).json()
    assert me["service"] is True
    assert session.scalar(select(User.platform_typ).where(User.id == uuid.UUID(me["id"]))) == (
        "service"
    )


def test_shadow_project_from_platform(platform, session):
    from app.db.models import Project

    tok = make_token(["methodologist"], projects=[PROJECT_A])
    r = platform.get(f"/projects/{PROJECT_A}", headers=auth(tok))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["id"] == PROJECT_A  # id тени = uuid платформы
    assert body["platform_project_id"] == PROJECT_A
    assert body["client"] == "ООО «Ромашка»"
    assert body["period_to"] == "2026-12-31"
    # Токен пользователя ушёл в платформу (сервисный туда не подходит).
    assert platform.fake.calls == [(PROJECT_A, tok)]
    # Повторно в течение 5 минут — без обращения к платформе.
    platform.get(f"/projects/{PROJECT_A}", headers=auth(tok))
    assert len(platform.fake.calls) == 1
    # Список — только проекты из токена.
    listed = platform.get("/projects", headers=auth(tok)).json()
    assert [p["id"] for p in listed] == [PROJECT_A]
    # Чужой проект — 403 no_project_access, тень не создаётся.
    r = platform.get(f"/projects/{PROJECT_B}", headers=auth(tok))
    assert r.status_code == 403
    assert r.json()["detail"] == "no_project_access"
    assert session.get(Project, uuid.UUID(PROJECT_B)) is None


def test_shadow_project_refreshed_after_ttl(platform, session):
    from app.db.models import Project, utcnow

    tok = make_token(["viewer"], projects=["*"])
    platform.get(f"/projects/{PROJECT_A}", headers=auth(tok))
    p = session.get(Project, uuid.UUID(PROJECT_A))
    p.platform_synced_at = utcnow() - timedelta(minutes=6)
    session.commit()
    platform.fake.projects[PROJECT_A]["name"] = "Аудит ООО «Ромашка», 2026–2027"
    r = platform.get(f"/projects/{PROJECT_A}", headers=auth(tok))
    assert r.json()["name"] == "Аудит ООО «Ромашка», 2026–2027"
    assert len(platform.fake.calls) == 2


def test_projects_are_created_only_in_platform(platform):
    tok = make_token(["methodologist"], projects=[PROJECT_A])
    platform.get(f"/projects/{PROJECT_A}", headers=auth(tok))
    r = platform.post(
        "/projects",
        json={"customer_id": str(uuid.uuid4()), "name": "Обход платформы"},
        headers=auth(tok),
    )
    assert r.status_code == 409
    r = platform.patch(f"/projects/{PROJECT_A}", json={"name": "Другое"}, headers=auth(tok))
    assert r.status_code == 409
    # Своё поле «Аттестации» менять можно.
    r = platform.patch(
        f"/projects/{PROJECT_A}", json={"scanner_engagement_id": 7}, headers=auth(tok)
    )
    assert r.status_code == 200
    assert r.json()["scanner_engagement_id"] == 7
    assert platform.post("/auth/token", json={"username": "a", "password": "b"}).status_code == 409


def _signed(client, envelope: dict):
    body = json.dumps(envelope, ensure_ascii=False).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return client.post("/events/platform", content=body, headers={"X-Signature": sig})


def _vector_event(etype: str) -> dict:
    events = json.loads((VEC / "events.json").read_text(encoding="utf-8"))["envelopes"]
    return dict(next(e for e in events if e["type"] == etype))


def test_project_archived_by_event_is_read_only(platform):
    tok = make_token(["methodologist"], projects=[PROJECT_A])
    platform.get(f"/projects/{PROJECT_A}", headers=auth(tok))
    obj = platform.post(
        f"/projects/{PROJECT_A}/objects",
        json={"kind": "gis", "name": "ГИС «Учёт»"},
        headers=auth(tok),
    )
    assert obj.status_code == 201, obj.text
    r = _signed(platform, _vector_event("platform.project.updated"))
    assert r.json() == {"status": "applied"}
    p = platform.get(f"/projects/{PROJECT_A}", headers=auth(tok)).json()
    assert p["status"] == "archived"
    r = platform.post(
        f"/projects/{PROJECT_A}/objects",
        json={"kind": "gis", "name": "Ещё объект"},
        headers=auth(tok),
    )
    assert r.status_code == 409
    assert r.json()["detail"] == "project_archived"
    # Чтение остаётся.
    assert platform.get(f"/projects/{PROJECT_A}/objects", headers=auth(tok)).status_code == 200


def test_revoked_key_rejected_immediately(platform):
    tok = make_token(["viewer"], projects=["*"])
    assert platform.get("/me", headers=auth(tok)).status_code == 200
    r = _signed(platform, _vector_event("platform.keys.rotated"))  # revoked: vec00001
    assert r.json() == {"status": "applied"}
    r = platform.get("/me", headers=auth(tok))
    assert r.status_code == 401
    # Токены ключа next по-прежнему принимаются.
    tok2 = make_token(["viewer"], projects=["*"], kid="20261104-vec00002")
    assert platform.get("/me", headers=auth(tok2)).status_code == 200


def test_unknown_kid_refetch_is_rate_limited():
    from app.integrations.platform.tokens import JwksCache

    now = [1000.0]
    calls: list[int] = []

    def fetch():
        calls.append(1)
        return JWKS

    cache = JwksCache("", fetch=fetch, clock=lambda: now[0])
    assert cache.get("20261104-vec00001") is not None
    assert cache.get("nope") is None
    assert len(calls) == 1  # только что перечитали — не чаще раза в 30 с
    now[0] += 31
    cache.get("nope")
    assert len(calls) == 2
    now[0] += 601
    cache.get("20261104-vec00001")
    assert len(calls) == 3  # кэш 10 минут


# ---------- Сводка и поиск ----------


def test_summary_contract(platform):
    tok = make_token(["methodologist"], projects=[PROJECT_A])
    r = platform.get(f"/summary?project={PROJECT_A}", headers=auth(tok))
    assert r.status_code == 200
    body = r.json()
    assert body["product"] == "grc"
    assert body["project_id"] == PROJECT_A
    assert body["link"] == f"/grc/?project={PROJECT_A}"
    assert body["data"] == {
        "systems": 0,
        "measures_percent": None,
        "measures_percent_all": None,
        "measures_unassessed_manual": 0,
        "measures_note": None,
        "measures_actions": [],
        "documents": {"ready": 0, "total": 0},
    }


def test_search_contract(platform):
    tok = make_token(["methodologist"], projects=[PROJECT_A])
    platform.get(f"/projects/{PROJECT_A}", headers=auth(tok))
    platform.post(
        f"/projects/{PROJECT_A}/objects",
        json={"kind": "gis", "name": "ГИС «Учёт»"},
        headers=auth(tok),
    )
    r = platform.get(f"/search?q=учёт&project={PROJECT_A}&limit=8", headers=auth(tok))
    items = r.json()["items"]
    assert items and items[0]["kind"] == "object"
    assert items[0]["link"].startswith("/grc/objects/")
    assert items[0]["link"].endswith(f"?project={PROJECT_A}")


# ---------- Outbox ----------


def _outbox(session):
    from app.db.models import OutboxEvent

    session.expire_all()
    return session.scalars(select(OutboxEvent).order_by(OutboxEvent.created_at)).all()


def test_audit_records_go_to_outbox_in_same_transaction(platform, session):
    tok = make_token(["methodologist"], projects=[PROJECT_A], sub=str(uuid.uuid4()))
    platform.get(f"/projects/{PROJECT_A}", headers=auth(tok))
    rows = [r for r in _outbox(session) if r.type == "audit.recorded"]
    actions = [json.loads(r.body)["data"]["action"] for r in rows]
    assert actions == ["user.shadow_create", "project.shadow_create"]
    env = json.loads(rows[1].body)
    assert env["source"] == "grc"
    assert env["project_id"] == PROJECT_A
    assert env["subject"].startswith("audit/")
    assert env["data"]["result"] == "success"
    assert env["data"]["object"] == f"project/{PROJECT_A}"
    assert env["data"]["actor"]["name"] == "Петров П. П."
    # Компактный JSON без \\u — подписывается и отправляется как есть.
    assert rows[1].body == json.dumps(env, ensure_ascii=False, separators=(",", ":"))


def test_local_mode_keeps_no_outbox(client, make_user, login, session):
    make_user("meth", "methodologist")
    login("meth")
    assert _outbox(session) == []


def test_delivery_statuses_and_retries(platform, session):
    from app import platform_events
    from app.db.models import utcnow

    platform.get("/me", headers=auth(make_token(["viewer"])))  # одна запись audit.recorded
    sent: list[tuple[str, bytes, dict]] = []

    def ok(url, body, headers):
        sent.append((url, body, headers))
        return 202, ""

    assert platform_events.deliver_due(session, sender=ok)["delivered"] == 1
    url, body, headers = sent[0]
    row = _outbox(session)[0]
    assert url == EVENTS_URL
    assert body == row.body.encode()
    assert headers["X-Platform-Product"] == "grc"
    assert headers["X-Event-Id"] == row.id
    assert headers["X-Signature"] == platform_events.sign(SECRET, body)
    assert row.status == "delivered"

    # 422 — rejected, без повторов.
    platform.get("/me", headers=auth(make_token(["viewer"])))
    platform_events.deliver_due(session, sender=lambda *a: (422, '{"detail":"rejected"}'))
    assert _outbox(session)[-1].status == "rejected"

    # 5xx — повторы 1, 5, 15, 60 мин, затем dead.
    platform.get("/me", headers=auth(make_token(["viewer"])))
    now = utcnow()
    for minutes in (1, 5, 15, 60):
        platform_events.deliver_due(session, sender=lambda *a: (503, ""), now=now)
        row = _outbox(session)[-1]
        assert row.status == "pending"
        nxt = row.next_at if row.next_at.tzinfo else row.next_at.replace(tzinfo=now.tzinfo)
        assert nxt - now == timedelta(minutes=minutes)
        # До срока не трогаем.
        assert platform_events.deliver_due(session, sender=ok, now=now)["delivered"] == 0
        now = nxt
    platform_events.deliver_due(session, sender=lambda *a: (503, ""), now=now)
    assert _outbox(session)[-1].status == "dead"


def test_duplicate_is_delivered(platform, session):
    from app import platform_events

    platform.get("/me", headers=auth(make_token(["viewer"])))
    platform_events.deliver_due(session, sender=lambda *a: (200, '{"duplicate":true}'))
    assert _outbox(session)[0].status == "delivered"


def test_outbox_screen_and_retry(platform, session):
    from app import platform_events

    platform.get("/me", headers=auth(make_token(["viewer"])))
    platform_events.deliver_due(session, sender=lambda *a: (422, ""))
    admin = make_token(["admin"], projects=["*"])
    st = platform.get("/outbox/status", headers=auth(admin)).json()
    assert st["outbox_enabled"] is True
    assert st["counts"]["rejected"] == 1
    rows = platform.get("/outbox?status=rejected", headers=auth(admin)).json()
    assert rows[0]["type"] == "audit.recorded"
    r = platform.post(f"/outbox/{rows[0]['id']}/retry", headers=auth(admin))
    assert r.json()["status"] == "pending"
    # Не администратору экран недоступен.
    viewer = make_token(["viewer"], projects=["*"])
    assert platform.get("/outbox/status", headers=auth(viewer)).status_code == 403


def _object_with_measures(session, project_id: uuid.UUID):
    from app.db.models import AssessedObject, ObjectMeasure

    o = AssessedObject(project_id=project_id, kind="gis", name="ГИС «Учёт»", regime="117")
    session.add(o)
    session.flush()
    for i, (method, status) in enumerate(
        [("auto", "implemented"), ("auto", "not_implemented"), ("manual", "unassessed")]
    ):
        session.add(
            ObjectMeasure(
                object_id=o.id,
                project_id=project_id,
                profile_id="fstec-117",
                measure_id=f"УПД.{i + 1}",
                group_code="УПД",
                title=f"Мера {i + 1}",
                position=i,
                origin="baseline",
                method=method,
                status=status,
            )
        )
    session.commit()
    return o


def test_assessment_updated_throttled_per_object(platform, session):
    from app import platform_events
    from app.db.models import ObjectMeasure, utcnow

    tok = make_token(["methodologist"], projects=[PROJECT_A])
    platform.get(f"/projects/{PROJECT_A}", headers=auth(tok))
    o = _object_with_measures(session, uuid.UUID(PROJECT_A))
    now = utcnow()
    assert platform_events.scan_assessments(session, now=now) == 1
    ev = [json.loads(r.body) for r in _outbox(session) if r.type == "grc.assessment.updated"]
    assert ev[0]["subject"] == f"system/{o.id}"
    assert ev[0]["project_id"] == PROJECT_A
    # Организационная мера без оценки — вне знаменателя: 1 из 2 = 50 %.
    assert ev[0]["data"] == {
        "system_id": str(o.id),
        "title": "ГИС «Учёт»",
        "percent": 50,
        "status": "in_progress",
        "regime": "117",
    }
    # Без изменений — тишина.
    assert platform_events.scan_assessments(session, now=now + timedelta(minutes=5)) == 0
    # Изменение раньше минуты не отправляется, позже — уходит последнее значение.
    m = session.scalar(select(ObjectMeasure).where(ObjectMeasure.measure_id == "УПД.2"))
    m.status = "implemented"
    session.commit()
    assert platform_events.scan_assessments(session, now=now + timedelta(seconds=30)) == 0
    assert platform_events.scan_assessments(session, now=now + timedelta(seconds=61)) == 1
    ev = [json.loads(r.body) for r in _outbox(session) if r.type == "grc.assessment.updated"]
    assert ev[-1]["data"]["percent"] == 100


def test_approval_requested_notifies_approvers_except_author(platform, session):
    from app import platform_events
    from app.db.models import GeneratedDocument

    a_sub, b_sub, c_sub, d_sub = (str(uuid.uuid4()) for _ in range(4))
    author = make_token(["methodologist", "approve"], projects=[PROJECT_A], sub=a_sub)
    platform.get(f"/projects/{PROJECT_A}", headers=auth(author))
    # Утверждающий проекта, утверждающий всех проектов, утверждающий чужого проекта.
    platform.get("/me", headers=auth(make_token(["assessor", "approve"], sub=b_sub)))
    platform.get("/me", headers=auth(make_token(["viewer", "approve"], ["*"], sub=c_sub)))
    platform.get("/me", headers=auth(make_token(["approve", "assessor"], [PROJECT_B], sub=d_sub)))
    me = platform.get("/me", headers=auth(author)).json()
    o = _object_with_measures(session, uuid.UUID(PROJECT_A))
    d = GeneratedDocument(
        id=uuid.uuid4(),
        object_id=o.id,
        project_id=o.project_id,
        doc_type="classification_act",
        title="Акт классификации ГИС «Учёт»",
        version=1,
        template_name="t",
        template_sha256="0" * 64,
        context_hash="0" * 64,
        context={},
        field_map=[],
        docx_sha256="0" * 64,
        docx_size=1,
        created_by=uuid.UUID(me["id"]),
    )
    session.add(d)
    session.commit()
    from app.db.models import User

    submitter = session.get(User, uuid.UUID(me["id"]))
    platform_events.document_approval_requested(session, d, submitter)
    session.commit()
    ev = next(
        json.loads(r.body) for r in _outbox(session) if r.type == "grc.document.approval_requested"
    )
    assert ev["subject"] == f"document/{d.id}"
    assert ev["data"]["author_sub"] == a_sub
    assert sorted(ev["notify"]["users"]) == sorted([b_sub, c_sub])
    assert ev["notify"]["link"] == f"/grc/objects/{o.id}?project={PROJECT_A}&tab=documents"


def test_vm_events_via_platform_webhook(platform):
    ev = _vector_event("vm.ticket.status_changed")
    assert _signed(platform, ev).json() == {"status": "unknown_ticket"}
