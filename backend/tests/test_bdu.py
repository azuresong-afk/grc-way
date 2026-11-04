"""БДУ ФСТЭК: разбор выгрузок, сравнение, применение, отметка «требует пересчёта»."""

import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from app.db.models import AuditRecord, BduImport, BduVuln
from app.domain.bdu import (
    BduFormatError,
    exploit_state,
    in_wild_state,
    parse_file,
    severity_scores,
    threat_code,
)
from app.domain.cvss import CvssError, base_score
from app.integrations.bdu.sample import THREAT_HEADER, VULN_HEADER, thrlist_xlsx, vullist_xlsx
from app.integrations.bdu.xlsx import XlsxError, read_rows, write_xlsx

XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


@pytest.fixture
def bdu_dir(tmp_path, monkeypatch):
    from app.core.config import get_settings

    d = tmp_path / "bdu"
    monkeypatch.setenv("GRC_BDU_DIR", str(d))
    get_settings.cache_clear()
    return d


def _file(tmp_path: Path, data: bytes, name: str = "f.xlsx") -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


# ---------- CVSS и нормализация ----------


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),  # пример 1 Методики 2025
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),  # пример 2 Методики 2025
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
        ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss31_base_score(vector, score):
    assert base_score(vector) == score


def test_cvss_rejects_broken_vector():
    with pytest.raises(CvssError, match="Нет базовых метрик"):
        base_score("AV:N/AC:L")
    with pytest.raises(CvssError, match="значение"):
        base_score("AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")


def test_value_normalization():
    assert threat_code("1") == ("УБИ.001", 1)
    assert threat_code("12.0") == ("УБИ.012", 12)
    assert threat_code("УБИ.190") == ("УБИ.190", 190)
    assert threat_code("абв") is None
    assert exploit_state("Существует в открытом доступе") == "public"
    assert exploit_state("Существует") == "exists"
    assert exploit_state("Данные уточняются") == "unknown"
    assert exploit_state("Информация отсутствует") == "none"
    assert in_wild_state("Да") == "yes"
    assert in_wild_state("Нет") == "no"
    assert in_wild_state("Данные уточняются") == "unknown"
    assert severity_scores(
        "Высокий уровень опасности (базовая оценка CVSS 2.0 составляет 10)\n"
        "Критический уровень опасности (базовая оценка CVSS 3.1 составляет 9,8)"
    ) == {"2.0": 10.0, "3.1": 9.8}


# ---------- Разбор файлов ----------


def test_reader_keeps_column_positions_with_gaps(tmp_path):
    p = _file(tmp_path, write_xlsx([["a", None, "c"], [], ["", "b"]]))
    assert list(read_rows(p)) == [["a", "", "c"], [], ["", "b"]]


def test_reader_rejects_non_zip(tmp_path):
    with pytest.raises(XlsxError):
        list(read_rows(_file(tmp_path, b"not a zip")))


def test_parse_thrlist(tmp_path):
    parsed = parse_file(_file(tmp_path, thrlist_xlsx()))
    assert parsed.kind == "threats" and parsed.header_row == 2
    t = parsed.rows["УБИ.140"]
    assert t["title"].startswith("Угроза приведения системы")
    assert (t["conf"], t["integ"], t["avail"]) == (False, False, True)
    # Версия — наибольшая «Дата последнего изменения данных».
    assert str(parsed.version) == "2025-07-15" and parsed.version_source == "rows"
    assert parsed.missing == []


def test_parse_vullist_fields_for_criticality(tmp_path):
    parsed = parse_file(_file(tmp_path, vullist_xlsx()))
    assert parsed.kind == "vulns" and parsed.header_row == 3
    v = parsed.rows["BDU:2025-01611"]
    # Версия CVSS — из «Уровня опасности», хотя столбец называется «CVSS 3.0».
    assert v["cvss3_vector"] == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    assert (v["cvss3_score"], v["cvss3_score_source"]) == (8.8, "bdu")
    assert (v["exploit"], v["in_wild"]) == ("unknown", "unknown")
    assert v["cve_ids"] == ["CVE-2024-55591"] and v["cwe_ids"] == ["CWE-266"]
    log4j = parsed.rows["BDU:2021-06061"]
    assert log4j["cvss3_version"] == "3.0" and log4j["cvss3_score"] == 10.0
    assert log4j["cvss_other"]["cvss2"]["score"] == 10.0
    assert log4j["in_wild"] == "yes"
    # Нет оценки в «Уровне опасности» — считается по вектору.
    no_score = parsed.rows["BDU:2026-00042"]
    assert (no_score["cvss3_score"], no_score["cvss3_score_source"]) == (9.1, "computed")
    # Только CVSS 2.0: оценки 3.x нет, специалист выберет версию сам (п. 13).
    old = parsed.rows["BDU:2015-07745"]
    assert old["cvss3_vector"] is None and old["cvss3_score"] is None
    assert str(parsed.version) == "2026-10-01" and parsed.version_source == "file"


def test_parse_finds_columns_by_header_in_any_order(tmp_path):
    header = list(reversed(VULN_HEADER))
    row = ["" for _ in header]
    row[header.index("Идентификатор")] = "BDU:2024-00001"
    row[header.index("Наименование уязвимости")] = "Уязвимость"
    row[header.index("CVSS 3.0")] = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    row[header.index("Наличие эксплойта")] = "Существует"
    p = _file(tmp_path, write_xlsx([["Выгрузка от 03.11.2026"], header, row]))
    parsed = parse_file(p)
    v = parsed.rows["BDU:2024-00001"]
    assert v["cvss3_score"] == 9.8 and v["exploit"] == "exists"
    assert str(parsed.version) == "2026-11-03" and parsed.version_source == "title"


def test_parse_reports_missing_and_bad_rows(tmp_path):
    header = ["Идентификатор", "Наименование уязвимости", "Описание уязвимости"]
    rows = [header, ["BDU:2024-00001", "А", ""], ["CVE-1", "Б", ""], ["BDU:2024-00002", "", ""]]
    parsed = parse_file(_file(tmp_path, write_xlsx(rows)))
    assert list(parsed.rows) == ["BDU:2024-00001"]
    assert parsed.skipped_count == 2
    assert [s["row"] for s in parsed.skipped] == [3, 4]
    assert "Наличие эксплойта" in parsed.missing
    assert "Эксплуатация в реальных атаках" in parsed.missing


def test_parse_rejects_foreign_file(tmp_path):
    with pytest.raises(BduFormatError, match="заголовков"):
        parse_file(_file(tmp_path, write_xlsx([["Имя", "Фамилия"], ["a", "b"]])))
    with pytest.raises(BduFormatError, match="Ожидалась"):
        parse_file(_file(tmp_path, thrlist_xlsx()), expect="vulns")
    with pytest.raises(BduFormatError, match="нет ни одной записи"):
        parse_file(_file(tmp_path, write_xlsx([THREAT_HEADER])))


# ---------- API ----------


@pytest.fixture
def env(make_user, login, bdu_dir):
    make_user("root", "admin")
    make_user("meth", "methodologist")
    return {"admin": login("root"), "meth": login("meth")}


def _upload(client, h, data: bytes, name="vullist.xlsx", **form):
    return client.post("/bdu/imports", headers=h, files={"file": (name, data, XLSX)}, data=form)


def test_threats_import_diff_apply_and_update(client, env, session, bdu_dir):
    h = env["admin"]
    r = _upload(client, h, thrlist_xlsx(1), "thrlist.xlsx")
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["kind"] == "threats" and d["status"] == "pending"
    assert d["summary"]["add"] == 6 and d["summary"]["has_changes"]
    assert d["export_version"] == "2025-07-15"
    assert len(list(bdu_dir.iterdir())) == 1  # файл в томе под sha256
    r = client.post(f"/bdu/imports/{d['id']}/apply", headers=h, json={})
    assert r.status_code == 200, r.text
    assert r.json()["applied"]["added"] == 6

    st = client.get("/bdu/status", headers=env["meth"]).json()
    assert st["threats"]["active"] == 6 and st["threats"]["version"] == "2025-07-15"

    r = _upload(client, h, thrlist_xlsx(2), "thrlist.xlsx")
    d2 = r.json()
    s = d2["summary"]
    assert (s["add"], s["update"], s["withdraw"], s["unchanged"]) == (1, 1, 0, 5)
    upd = next(i for i in d2["items"] if i["change"] == "update")
    assert upd["key"] == "УБИ.170"
    assert set(upd["fields"]) == {"description", "changed_on"}
    assert d2["field_titles"]["description"] == "Описание"
    client.post(f"/bdu/imports/{d2['id']}/apply", headers=h, json={})

    lst = client.get("/bdu/threats", headers=env["meth"], params={"q": "222"})
    assert lst.headers["X-Total-Count"] == "1"
    t = client.get("/bdu/threats/УБИ.170", headers=env["meth"]).json()
    assert t["changed_version"] == "2026-10-20" and t["first_version"] == "2025-07-15"
    assert t["description"].endswith("резервных копий.")


def test_vulns_criticality_change_marks_recalc(client, env, session):
    h = env["admin"]
    d = _upload(client, h, vullist_xlsx(1)).json()
    assert d["summary"]["add"] == 6
    client.post(f"/bdu/imports/{d['id']}/apply", headers=h, json={}).raise_for_status()
    v = session.get(BduVuln, "BDU:2025-01611")
    assert v.criticality_changed_at is None and v.first_version.isoformat() == "2026-10-01"

    d2 = _upload(client, h, vullist_xlsx(2)).json()
    s = d2["summary"]
    assert (s["add"], s["update"], s["withdraw"], s["criticality"]) == (1, 2, 1, 1)
    assert s["crit_ids"] == ["BDU:2025-01611"]
    # Критичные изменения — первыми, с полями «было → стало».
    first = d2["items"][0]
    assert first["key"] == "BDU:2025-01611" and first["criticality"] is True
    assert first["fields"]["exploit"] == ["unknown", "public"]
    assert first["fields"]["in_wild"] == ["unknown", "yes"]
    nginx = next(i for i in d2["items"] if i["key"] == "BDU:2025-03219")
    assert nginx["criticality"] is False and set(nginx["fields"]) == {"description"}
    # 6 записей в файле при 6 загруженных — выгрузка не «усохла».
    codes = {w["code"] for w in d2["warnings"]}
    assert "shrink" not in codes

    r = client.post(f"/bdu/imports/{d2['id']}/apply", headers=h, json={})
    assert r.status_code == 200, r.text
    assert r.json()["applied"] == {
        "added": 1, "updated": 2, "restored": 0, "withdrawn": 1, "criticality": 1
    }  # fmt: skip
    session.expire_all()
    v = session.get(BduVuln, "BDU:2025-01611")
    assert v.criticality_changed_at is not None
    assert v.criticality_changes["exploit"] == ["unknown", "public"]
    assert session.get(BduVuln, "BDU:2025-03219").criticality_changed_at is None
    gone = session.get(BduVuln, "BDU:2015-07745")
    assert gone.withdrawn_at is not None  # не удалена

    viewer = env["meth"]
    lst = client.get("/bdu/vulns", headers=viewer, params={"crit_changed": "true"})
    assert [x["bdu_id"] for x in lst.json()] == ["BDU:2025-01611"]
    one = client.get("/bdu/vulns/BDU:2025-01611", headers=viewer).json()
    assert one["e_level"] == "in_wild" and one["criticality_changed_version"] == "2026-11-01"
    assert (
        client.get("/bdu/vulns", headers=viewer, params={"q": "CVE-2024-6387"}).json()[0]["bdu_id"]
        == "BDU:2024-04835"
    )
    assert client.get("/bdu/vulns", headers=viewer).headers["X-Total-Count"] == "6"
    st = client.get("/bdu/status", headers=viewer).json()["vulns"]
    assert (st["active"], st["withdrawn"], st["criticality_last"]) == (6, 1, 1)

    actions = session.scalars(select(AuditRecord.action).order_by(AuditRecord.id)).all()
    assert actions.count("bdu.import.apply") == 2


def test_same_file_again_has_no_changes_and_closes(client, env):
    h = env["admin"]
    d = _upload(client, h, vullist_xlsx(1)).json()
    client.post(f"/bdu/imports/{d['id']}/apply", headers=h, json={}).raise_for_status()
    again = _upload(client, h, vullist_xlsx(1)).json()
    assert again["summary"]["has_changes"] is False
    assert [w["code"] for w in again["warnings"]] == ["same_file"]
    # Предупреждение есть — нужно подтверждение, даже если изменений нет.
    r = client.post(f"/bdu/imports/{again['id']}/apply", headers=h, json={})
    assert r.status_code == 409 and r.headers["X-Error-Code"] == "ack_required"
    r = client.post(f"/bdu/imports/{again['id']}/apply", headers=h, json={"ack_warnings": True})
    assert r.status_code == 200 and r.json()["applied"]["updated"] == 0


def test_older_and_partial_export_need_ack(client, env, session):
    h = env["admin"]
    d = _upload(client, h, vullist_xlsx(2)).json()
    client.post(f"/bdu/imports/{d['id']}/apply", headers=h, json={}).raise_for_status()
    header_only = write_xlsx([VULN_HEADER, ["BDU:2025-01611", "Уязвимость FortiOS"]])
    p = _upload(client, h, header_only, export_version="2026-10-15").json()
    codes = {w["code"] for w in p["warnings"]}
    assert {"older", "shrink"} <= codes
    assert p["version_source"] == "user"
    r = client.post(f"/bdu/imports/{p['id']}/apply", headers=h, json={})
    assert r.status_code == 409
    assert (
        session.scalar(select(BduImport.status).where(BduImport.id == uuid.UUID(p["id"])))
        == "pending"
    )


def test_new_upload_supersedes_and_stale_diff_rejected(client, env, session, bdu_dir):
    h = env["admin"]
    first = _upload(client, h, vullist_xlsx(1)).json()
    second = _upload(client, h, vullist_xlsx(1)).json()
    r = client.post(f"/bdu/imports/{first['id']}/apply", headers=h, json={})
    assert r.status_code == 409 and "более новая" in r.json()["detail"]
    # Данные изменились после сравнения (применили другую выгрузку в обход) — отказ.
    from app.domain import bdu_import
    from app.domain.bdu import parse_file as pf

    other = _file(bdu_dir.parent, vullist_xlsx(2), "other.xlsx")
    parsed = pf(other)
    row = session.get(BduImport, uuid.UUID(second["id"]))
    bdu_import.apply(session, parsed, row, version=None)
    session.commit()
    r = client.post(f"/bdu/imports/{second['id']}/apply", headers=h, json={})
    assert r.status_code == 409 and "изменились" in r.json()["detail"]


def test_upload_rejections_and_permissions(client, env, session):
    r = _upload(client, env["meth"], vullist_xlsx(1))
    assert r.status_code == 403
    r = _upload(client, env["admin"], b"%PDF-1.4", name="vullist.pdf")
    assert r.status_code == 422 and "XLSX" in r.json()["detail"]
    r = _upload(client, env["admin"], b"PK\x03\x04garbage", name="vullist.xlsx")
    assert r.status_code == 422
    r = _upload(client, env["admin"], write_xlsx([["a", "b"]]))
    assert r.status_code == 422 and r.headers["X-Error-Code"] == "bdu_format"
    r = _upload(client, env["admin"], thrlist_xlsx(), kind="vulns")
    assert r.status_code == 422 and "Ожидалась" in r.json()["detail"]
    r = _upload(client, env["admin"], thrlist_xlsx(), export_version="01.11.2026")
    assert r.status_code == 422
    rejected = session.scalars(
        select(AuditRecord).where(AuditRecord.action == "bdu.import.rejected")
    ).all()
    assert len(rejected) == 4
