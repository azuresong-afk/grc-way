"""Ручная оценка: файлы доказательств, интервью, осмотр, отзыв, подтверждение меры."""

import io
import zipfile

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.security import hash_password
from app.db.models import AuditRecord, Evidence, EvidenceFile, ObjectMeasure, User
from app.domain.evidence_files import EvidenceFileError, clean_name, detect, store
from tests.conftest import PASSWORD
from tests.test_scanner_import import _build, _import, _measures
from tests.test_scanner_import import env as _scanner_env  # noqa: F401 — фикстура

PDF = b"%PDF-1.7\n1 0 obj << >> endobj\ntrailer << >>\n%%EOF\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def _ooxml(part: str, macros: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr(part, "<doc/>")
        if macros:
            z.writestr("word/vbaProject.bin", b"\x00macro")
    return buf.getvalue()


def _odt(macros: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        z.writestr("content.xml", "<office:document-content/>")
        if macros:
            z.writestr("Basic/Standard/Module1.xml", "<script/>")
    return buf.getvalue()


@pytest.fixture
def env(request):
    """Проект, объект «ГИС» К2 с хостами и пользователи — как в тестах импорта."""
    return request.getfixturevalue("_scanner_env")


@pytest.fixture(autouse=True)
def evidence_dir(tmp_path, monkeypatch):
    from app.core.config import get_settings

    d = tmp_path / "evidence"
    monkeypatch.setenv("GRC_EVIDENCE_DIR", str(d))
    monkeypatch.setenv("GRC_EVIDENCE_MAX_MB", "1")
    get_settings.cache_clear()
    yield d
    get_settings.cache_clear()


# ---------- Проверка файлов ----------


def _check(tmp_path, name: str, content: bytes) -> str:
    p = tmp_path / "probe"
    p.write_bytes(content)
    return detect(p, name)


@pytest.mark.parametrize(
    ("ext", "content"),
    [
        ("pdf", PDF),
        ("png", PNG),
        ("jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 16),
        ("docx", _ooxml("word/document.xml")),
        ("xlsx", _ooxml("xl/workbook.xml")),
        ("odt", _odt()),
        ("txt", "Журнал: вход выполнен".encode()),
        ("txt", "Журнал в cp1251".encode("cp1251")),
        ("csv", b"host;status\n10.0.0.1;ok\n"),
        ("json", b'{"a": 1}'),
        ("xml", b'<?xml version="1.0"?><a/>'),
        ("zip", _ooxml("any.txt")),
    ],
)
def test_detect_accepts_whitelisted_types(tmp_path, ext, content):
    assert _check(tmp_path, ext, content)


@pytest.mark.parametrize(
    ("ext", "content", "code"),
    [
        ("exe", b"MZ\x90\x00", "file_type"),
        ("html", b"<html><script>alert(1)</script>", "file_type"),
        ("svg", b"<svg onload=alert(1)>", "file_type"),
        ("pdf", b"<html>not a pdf</html>", "file_rejected"),  # подмена расширения
        ("png", PDF, "file_rejected"),
        ("docx", _ooxml("word/document.xml", macros=True), "file_macros"),
        ("docx", _ooxml("xl/workbook.xml"), "file_rejected"),  # xlsx под видом docx
        ("odt", _odt(macros=True), "file_macros"),
        ("zip", b"PK\x03\x04garbage", "file_rejected"),
        ("txt", b"MZ\x00\x00binary", "file_rejected"),
        ("json", b"{broken", "file_rejected"),
        ("xml", b"plain text", "file_rejected"),
        ("pdf", b"", "file_rejected"),
    ],
)
def test_detect_rejects(tmp_path, ext, content, code):
    with pytest.raises(EvidenceFileError) as e:
        _check(tmp_path, ext, content)
    assert e.value.code == code


def test_store_dedups_by_sha_and_limits_size(tmp_path):
    d = tmp_path / "vol"
    a = store([PDF[:10], PDF[10:]], "акт.pdf", d, 1024)
    b = store([PDF], "копия.pdf", d, 1024)
    assert a.sha256 == b.sha256 and a.path == d / a.sha256 and a.path.read_bytes() == PDF
    assert sorted(p.name for p in d.iterdir()) == [a.sha256]
    with pytest.raises(EvidenceFileError) as e:
        store([b"x" * 600, b"x" * 600], "big.txt", d, 1024)
    assert e.value.code == "file_too_large"
    # Временные файлы не остаются ни после отказа, ни после успеха.
    assert sorted(p.name for p in d.iterdir()) == [a.sha256]


def test_clean_name():
    assert clean_name("C:\\Users\\x\\Акт осмотра.pdf") == "Акт осмотра.pdf"
    assert clean_name("../../etc/passwd") == "passwd"
    assert clean_name("a\x00b\r\n.txt") == "ab.txt"
    assert clean_name("") == "file"
    assert len(clean_name("я" * 300 + ".pdf")) == 200


# ---------- API ----------


def _upload(client, h, mid, name, content, who="exp", **fields):
    data = {"summary": "Положение о защите информации, утверждено приказом №12", **fields}
    return client.post(
        f"/object-measures/{mid}/evidence",
        headers=h[who],
        data=data,
        files={"file": (name, content, "application/octet-stream")},
    )


def _confirm(client, h, mid, who="exp", **body):
    return client.post(f"/object-measures/{mid}/confirm", headers=h[who], json=body)


def _set_status(client, h, mid, status):
    r = client.patch(f"/object-measures/{mid}", headers=h["exp"], json={"status": status})
    assert r.status_code == 200, r.text
    return r.json()


def test_file_evidence_upload_and_download(client, env, session, evidence_dir):
    h, o, _ = env
    _build(client, h, o["id"])
    vu = _measures(client, h, o["id"])["ВУ"]

    r = _upload(client, h, vu["id"], "C:\\docs\\Положение.pdf", PDF, category="document")
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["kind"] == "file" and ev["data"]["category"] == "document"
    assert ev["file"]["name"] == "Положение.pdf" and ev["file"]["mime"] == "application/pdf"
    assert ev["file"]["size"] == len(PDF) and ev["created_by_name"] == "Козлов К. К."
    assert (evidence_dir / ev["file"]["sha256"]).read_bytes() == PDF

    # Скачивает любой участник проекта; отдача только как вложение.
    r = client.get(f"/files/{ev['file']['id']}", headers=h["viewer"])
    assert r.status_code == 200 and r.content == PDF
    assert r.headers["content-type"] == "application/pdf"
    assert r.headers["content-disposition"].startswith("attachment;")
    assert "filename*=UTF-8''%D0%9F" in r.headers["content-disposition"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in r.headers["content-security-policy"]
    assert session.scalars(select(AuditRecord).where(AuditRecord.action == "files.download")).one()

    # Мера показывает число ручных доказательств; список — вместе с автоматическими.
    assert _measures(client, h, o["id"])["ВУ"]["manual_evidence"] == 1
    lst = client.get(f"/object-measures/{vu['id']}/evidence", headers=h["viewer"]).json()
    assert [e["kind"] for e in lst] == ["file"]
    assert client.get(f"/evidence/{ev['id']}", headers=h["viewer"]).json()["id"] == ev["id"]

    # Тот же файл ещё раз — новая запись, одна копия в томе.
    r = _upload(client, h, vu["id"], "копия.pdf", PDF)
    assert r.status_code == 201
    assert len(list(evidence_dir.iterdir())) == 1
    assert len(session.scalars(select(EvidenceFile)).all()) == 2


def test_file_rejections_and_permissions(client, env, session, evidence_dir):
    h, o, _ = env
    _build(client, h, o["id"])
    vu = _measures(client, h, o["id"])["ВУ"]

    r = _upload(client, h, vu["id"], "payload.html", b"<script>alert(1)</script>")
    assert r.status_code == 422 and "не принимается" in r.json()["detail"]
    r = _upload(client, h, vu["id"], "акт.pdf", b"<html>fake</html>")
    assert r.status_code == 422 and "PDF" in r.json()["detail"]
    r = _upload(client, h, vu["id"], "big.txt", b"a" * (1024 * 1024 + 1))
    assert r.status_code == 413 and r.headers["x-error-code"] == "file_too_large"
    r = _upload(client, h, vu["id"], "м.docx", _ooxml("word/document.xml", macros=True))
    assert r.status_code == 422 and "макрос" in r.json()["detail"]
    # Отказы попадают в журнал, в томе ничего не остаётся.
    rejected = session.scalars(
        select(AuditRecord).where(AuditRecord.action == "evidence.rejected")
    ).all()
    assert len(rejected) == 4
    assert not evidence_dir.exists() or list(evidence_dir.iterdir()) == []

    # Без файла, без описания, с неизвестной категорией.
    r = client.post(
        f"/object-measures/{vu['id']}/evidence", headers=h["exp"], data={"summary": "x"}
    )
    assert r.status_code == 422
    r = _upload(client, h, vu["id"], "a.pdf", PDF, summary="  ")
    assert r.status_code == 422
    r = _upload(client, h, vu["id"], "a.pdf", PDF, category="virus")
    assert r.status_code == 422

    # Загружает только эксперт.
    for who in ("meth", "viewer", "boss"):
        assert _upload(client, h, vu["id"], "a.pdf", PDF, who=who).status_code == 403

    # Чужой проект: ни меры, ни файла не видно.
    r = _upload(client, h, vu["id"], "a.pdf", PDF)
    fid = r.json()["file"]["id"]
    u = User(username="other", display_name="Другой", password_hash=hash_password(PASSWORD))
    u.set_roles({"assessor"})
    session.add(u)
    session.commit()
    tok = client.post("/auth/token", json={"username": "other", "password": PASSWORD}).json()
    other = {"Authorization": f"Bearer {tok['access_token']}"}
    assert client.get(f"/files/{fid}", headers=other).status_code == 404
    assert client.get(f"/object-measures/{vu['id']}/evidence", headers=other).status_code == 404

    # Файл пропал из тома — честная ошибка, а не пустой ответ.
    for p in evidence_dir.iterdir():
        p.unlink()
    r = client.get(f"/files/{fid}", headers=h["viewer"])
    assert r.status_code == 410 and r.headers["x-error-code"] == "file_missing"


def test_interview_and_inspection(client, env):
    h, o, _ = env
    _build(client, h, o["id"])
    vu = _measures(client, h, o["id"])["ВУ"]
    url = f"/object-measures/{vu['id']}/evidence"

    r = client.post(
        url,
        headers=h["exp"],
        json={
            "kind": "interview",
            "summary": "Администратор описал порядок выявления инцидентов",
            "held_on": "2026-11-02",
            "participants": "Петров П. П., администратор безопасности",
            "details": "В: Кто ведёт журнал? О: Администратор безопасности.",
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["data"]["participants"].startswith("Петров")
    r = client.post(
        url,
        headers=h["exp"],
        json={
            "kind": "inspection",
            "summary": "Серверная заперта, журнал доступа ведётся",
            "held_on": "2026-11-03",
            "place": "Серверная, каб. 105",
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["data"]["place"] == "Серверная, каб. 105"

    # Интервью без даты или без опрошенных, дата в будущем, неизвестный вид.
    bad = [
        {"kind": "interview", "summary": "x", "participants": "П"},
        {"kind": "interview", "summary": "x", "held_on": "2026-11-02"},
        {"kind": "inspection", "summary": "x", "held_on": "2999-01-01"},
        {"kind": "scanner", "summary": "x"},
        {"kind": "file", "summary": "x"},
    ]
    for body in bad:
        r = client.post(url, headers=h["exp"], json=body)
        assert r.status_code == 422, body
    assert "кого опрашивали" in client.post(url, headers=h["exp"], json=bad[1]).json()["detail"]
    assert _measures(client, h, o["id"])["ВУ"]["manual_evidence"] == 2


def test_confirm_organizational_measure(client, env, session):
    h, o, _ = env
    _build(client, h, o["id"])
    vu = _measures(client, h, o["id"])["ВУ"]
    mid = vu["id"]

    # Не оценена — подтверждать нечего; «Реализована» без доказательств — нельзя.
    r = _confirm(client, h, mid)
    assert r.status_code == 409 and "статус" in r.json()["detail"]
    _set_status(client, h, mid, "implemented")
    r = _confirm(client, h, mid)
    assert r.status_code == 409 and "доказательств" in r.json()["detail"]

    ev = _upload(client, h, mid, "Положение.pdf", PDF).json()
    # Наблюдатель и методист не подтверждают.
    for who in ("viewer", "meth"):
        assert _confirm(client, h, mid, who=who).status_code == 403
    # Гонка: статус сменили, пока карточка была открыта.
    r = _confirm(client, h, mid, status="partial")
    assert r.status_code == 409 and r.headers["x-error-code"] == "status_changed"

    r = _confirm(client, h, mid, status="implemented", comment="Проверено по документу")
    assert r.status_code == 200, r.text
    m = r.json()
    assert m["confirmed_status"] == "implemented" and m["confirmed_by_name"] == "Козлов К. К."
    assert m["confirm_comment"] == "Проверено по документу" and m["confirmed_at"]
    rec = session.scalars(select(AuditRecord).where(AuditRecord.action == "measures.confirm")).one()
    assert rec.details["evidence"] == [ev["id"]]
    lst = client.get(f"/object-measures/{mid}/evidence", headers=h["viewer"]).json()
    assert lst[0]["in_confirmation"] is True

    s = client.get(f"/objects/{o['id']}/measure-set", headers=h["viewer"]).json()
    assert s["confirmed"] == 1
    q = client.get(f"/objects/{o['id']}/measures?confirmed=true", headers=h["viewer"]).json()
    assert [x["measure_id"] for x in q] == ["ВУ"]

    # Комментарий и ответственный подтверждение не снимают, смена статуса — снимает.
    r = client.patch(f"/object-measures/{mid}", headers=h["exp"], json={"comment": "ок"})
    assert r.json()["confirmed_at"] is not None
    m = _set_status(client, h, mid, "partial")
    assert m["confirmed_at"] is None and m["confirmed_status"] is None
    assert _confirm(client, h, mid).status_code == 200

    # Отзыв доказательства, на котором стоит подтверждение, снимает его.
    r = client.post(f"/evidence/{ev['id']}/withdraw", headers=h["exp"], json={"reason": "  "})
    assert r.status_code == 422
    r = client.post(
        f"/evidence/{ev['id']}/withdraw",
        headers=h["exp"],
        json={"reason": "Приложена не та редакция"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["withdrawn_by_name"] == "Козлов К. К." and r.json()["in_confirmation"] is False
    m = _measures(client, h, o["id"])["ВУ"]
    assert m["confirmed_at"] is None and m["manual_evidence"] == 0
    q = select(AuditRecord).where(AuditRecord.action == "evidence.withdraw")
    rec = session.scalars(q).one()
    assert rec.details["confirmation_reset"] is True
    # Отозванное остаётся в истории и не отзывается повторно.
    assert len(client.get(f"/object-measures/{mid}/evidence", headers=h["viewer"]).json()) == 1
    r = client.post(f"/evidence/{ev['id']}/withdraw", headers=h["exp"], json={"reason": "ещё"})
    assert r.status_code == 409
    # Без действующих доказательств «Частично» снова не подтверждается.
    assert _confirm(client, h, mid).status_code == 409


def test_confirm_not_implemented_and_not_applicable(client, env):
    h, o, _ = env
    _build(client, h, o["id"])
    ms = _measures(client, h, o["id"])
    vu = ms["ВУ"]
    other = next(m for m in ms.values() if m["method"] == "manual" and m["measure_id"] != "ВУ")

    _set_status(client, h, vu["id"], "not_implemented")
    assert _confirm(client, h, vu["id"]).status_code == 200

    _set_status(client, h, other["id"], "not_applicable")
    r = _confirm(client, h, other["id"])
    assert r.status_code == 409 and "не применима" in r.json()["detail"]
    r = _confirm(client, h, other["id"], comment="Нет беспроводных сетей")
    assert r.status_code == 200


def test_confirm_excluded_measure_is_blocked_and_exclusion_resets(client, env):
    h, o, _ = env
    _build(client, h, o["id"])
    vu = _measures(client, h, o["id"])["ВУ"]
    _set_status(client, h, vu["id"], "not_implemented")
    assert _confirm(client, h, vu["id"]).status_code == 200
    r = client.patch(
        f"/object-measures/{vu['id']}",
        headers=h["meth"],
        json={"adaptation": "excluded", "adaptation_reason": "Не актуально"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["confirmed_at"] is None
    r = _confirm(client, h, vu["id"])
    assert r.status_code == 409 and "Исключённая" in r.json()["detail"]


def test_confirm_auto_measure_by_scanner_and_reimport_keeps_it(client, env):
    h, o, _ = env
    _build(client, h, o["id"])
    _import(client, h, o["id"], run_id=7)
    m = _measures(client, h, o["id"])["УПД.8"]
    assert m["status"] == "not_implemented" and m["status_source"] == "auto"

    # Совпадает с «Сканером» — достаточно автоматического доказательства.
    impl = next(
        x
        for x in _measures(client, h, o["id"]).values()
        if x["status"] == "implemented" and x["status_source"] == "auto"
    )
    r = _confirm(client, h, impl["id"])
    assert r.status_code == 200, r.text
    lst = client.get(f"/object-measures/{impl['id']}/evidence", headers=h["viewer"]).json()
    assert lst[0]["kind"] == "scanner" and lst[0]["in_confirmation"] is True
    # Автоматическое доказательство не отзывается.
    r = client.post(f"/evidence/{lst[0]['id']}/withdraw", headers=h["exp"], json={"reason": "x"})
    assert r.status_code == 409

    # Вручную «Реализована» вопреки «Сканеру» — нужно ручное доказательство.
    _set_status(client, h, m["id"], "implemented")
    r = _confirm(client, h, m["id"])
    assert r.status_code == 409 and "расходится" in r.json()["detail"]
    _upload(client, h, m["id"], "настройки.txt", b"PasswordAuthentication no\n", category="config")
    assert _confirm(client, h, m["id"]).status_code == 200

    # Подтверждённая мера, взятая у «Сканера», не меняется повторным импортом.
    before = _measures(client, h, o["id"])
    out = _import(client, h, o["id"], run_id=8)
    assert out.status_code == 201, out.text
    after = _measures(client, h, o["id"])
    assert after[impl["measure_id"]]["status"] == before[impl["measure_id"]]["status"]
    assert after[impl["measure_id"]]["confirmed_at"] is not None


def test_archived_object_is_read_only(client, env):
    h, o, _ = env
    _build(client, h, o["id"])
    vu = _measures(client, h, o["id"])["ВУ"]
    r = client.patch(f"/objects/{o['id']}", headers=h["meth"], json={"status": "archived"})
    assert r.status_code == 200, r.text
    assert _upload(client, h, vu["id"], "a.pdf", PDF).status_code == 409
    assert _confirm(client, h, vu["id"]).status_code == 409


def test_evidence_kinds_constraint(client, session, env):
    # Доказательство-файл без файла БД не примет.
    h, o, _ = env
    _build(client, h, o["id"])
    m = session.scalars(select(ObjectMeasure)).first()
    session.add(
        Evidence(
            object_measure_id=m.id,
            object_id=m.object_id,
            project_id=m.project_id,
            measure_id=m.measure_id,
            kind="file",
            summary="x",
            data={},
        )
    )
    with pytest.raises(IntegrityError):
        session.commit()
