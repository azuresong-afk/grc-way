"""Методика оценки критичности уязвимостей 2025 и нормативные документы (задача 2.6)."""

import copy
import shutil
from decimal import Decimal
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select

from app.db.models import AuditRecord, RefDocument, RefVulnMethodology
from app.domain.ref_documents import DocumentError
from app.domain.ref_documents import parse as parse_documents
from app.domain.vuln_criticality import InputError, MethodologyError, compute, validate
from app.refs.loader import load_reference

REFERENCE = Path(__file__).resolve().parents[2] / "reference"
FILE = REFERENCE / "vuln-criticality" / "fstec-2025.yaml"
DOCS = REFERENCE / "normative" / "documents.yaml"
_META = {"id", "title", "version", "origin", "source"}


def _definition() -> dict:
    data = yaml.safe_load(FILE.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if k not in _META}


def _indicator(defn: dict, code: str) -> dict:
    return next(i for i in defn["indicators"] if i["code"] == code)


# ---------- Примеры приложения ----------


def test_example_1_fortios_is_medium():
    """Пример 1: 8,8 × 0,9 × (0,1 + 0,5) ≈ 4,75 — «Средний»."""
    out = compute(
        _definition(),
        {"cvss": "8.8", "K": ["K2"], "L": ["L3"], "P": ["P1"], "E": ["E3"], "H": ["H2"]},
    )
    assert out.groups == {"infr": "0.9", "at": "0.1", "imp": "0.5"}
    assert out.v_exact == "4.752"
    assert out.v == "4.75"
    assert (out.level["code"], out.level["title"]) == ("medium", "Средний")
    assert out.level["condition"] == "2,0 ≤ V < 5,0"
    assert out.level["deadline"]["value"] == 4 and out.level["deadline"]["unit"] == "weeks"
    by = {t["indicator"]: t for t in out.trace}
    # Слагаемые I_infr — как в тексте примера: 0,45 + 0,12 + 0,33.
    assert (by["K"]["product"], by["L"]["product"], by["P"]["product"]) == ("0.45", "0.12", "0.33")
    assert by["K"]["value_title"] == "Уязвимости подвержены межсетевые экраны"
    assert by["cvss"]["score"] == "8.8"


def test_example_2_ingress_nginx_is_critical_by_max_rule():
    """Пример 2: 9,8 × 1,08 × (0,3 + 0,5) ≈ 8,47 — «Критический»; K и L — наибольшие."""
    out = compute(
        _definition(),
        {
            "cvss": "9.8",
            "K": ["K1", "K5", "K6", "K7"],
            "L": ["L1", "L2", "L3"],
            "P": ["P1"],
            "E": ["E2"],
            "H": ["H1"],
        },
    )
    assert out.groups["infr"] == "1.08"
    assert (out.v_exact, out.v) == ("8.4672", "8.47")
    assert (out.level["code"], out.level["title"]) == ("critical", "Критический")
    assert out.level["deadline"]["value"] == 24 and out.level["deadline"]["unit"] == "hours"
    by = {t["indicator"]: t for t in out.trace}
    assert (by["K"]["value"], by["K"]["product"]) == ("K1", "0.55")
    assert (by["L"]["value"], by["L"]["product"]) == ("L1", "0.2")
    assert by["K"]["rule"] == "наибольшее из значений"
    assert len(by["K"]["chosen"]) == 4


def test_examples_in_file_are_self_checked():
    examples = _definition()["examples"]
    assert [e["expected"]["v"] for e in examples] == ["4.75", "8.47"]
    assert [e["expected"]["level"] for e in examples] == ["medium", "critical"]


# ---------- Таблицы 1 и 2 ----------


def test_table_1_weights_and_values_match_methodology():
    d = _definition()
    weights = {i["code"]: Decimal(str(i["weight"])) for i in d["indicators"]}
    assert weights == {
        k: Decimal(v)
        for k, v in {"K": "0.5", "L": "0.2", "P": "0.3", "E": "1.0", "H": "1.0"}.items()
    }
    scores = {i["code"]: [str(v["score"]) for v in i["values"]] for i in d["indicators"]}
    assert scores["K"] == ["1.1", "0.9", "0.9", "0.8", "0.7", "0.5", "0.4", "0.1"]
    assert scores["L"] == ["1.0", "0.8", "0.6", "0.5"]
    assert scores["P"] == ["1.1", "0.6"]
    assert scores["E"] == ["0.6", "0.3", "0.1"]
    assert scores["H"] == [
        "0.5",
        "0.5",
        "0.4",
        "0.34",
        "0.3",
        "0.3",
        "0.26",
        "0.22",
        "0.2",
        "0.18",
        "0.12",
        "0.1",
    ]
    # «Итог» таблицы 1 = вес × значение; проверяем несколько строк.
    k = _indicator(d, "K")
    assert [str(Decimal(str(k["weight"])) * Decimal(str(v["score"]))) for v in k["values"][:2]] == [
        "0.55",
        "0.45",
    ]
    # У каждого показателя — пункт и строка таблицы 1.
    assert all(i["source"]["table"] == "1" and i["source"]["clause"] for i in d["indicators"])
    assert {i["code"]: i["multiple"] for i in d["indicators"]} == {
        "K": "max",
        "L": "max",
        "P": "single",
        "E": "max",
        "H": "max",
    }


@pytest.mark.parametrize(
    ("v", "level"),
    [
        ("0", "low"),
        ("1.99", "low"),
        ("2.0", "medium"),
        ("4.99", "medium"),
        ("5.0", "high"),
        ("8.0", "high"),
        ("8.01", "critical"),
        ("10", "critical"),
    ],
)
def test_table_2_boundaries(v, level):
    from app.domain.vuln_criticality import level_for

    assert level_for(_definition(), Decimal(v))["code"] == level


def test_level_uses_rounded_value():
    """V округляется до двух знаков, и уровень — по округлённому: 8,004 → 8,00 «Высокий»."""
    # Значения таблицы 1 не дают V рядом с 8,0 — меняем оценку E1 в копии.
    d = copy.deepcopy(_definition())
    d["examples"] = []
    _indicator(d, "E")["values"][0]["score"] = 0.241
    out = compute(d, {"cvss": "10", "K": "K2", "L": "L4", "P": "P1", "E": "E1", "H": "H1"})
    # 10 × (0,45 + 0,1 + 0,33) × (0,241 + 0,5) = 10 × 0,88 × 0,741 = 6,5208
    assert out.v == "6.52" and out.level["code"] == "high"
    _indicator(d, "E")["values"][0]["score"] = 0.40955
    out = compute(d, {"cvss": "10", "K": "K2", "L": "L4", "P": "P1", "E": "E1", "H": "H1"})
    # 10 × 0,88 × 0,90955 = 8,00404 → 8,00 — граница «Высокого».
    assert (out.v_exact, out.v, out.level["code"]) == ("8.00404", "8.00", "high")


def test_certified_szi_is_always_critical():
    """П. 4: уязвимость сертифицированного СЗИ — критический уровень при любом V."""
    out = compute(
        _definition(),
        {
            "cvss": "8.8",
            "K": ["K2"],
            "L": ["L3"],
            "P": ["P1"],
            "E": ["E3"],
            "H": ["H2"],
            "certified_szi": True,
        },
    )
    assert out.v == "4.75"
    assert out.level["code"] == "critical" and out.level_by_v == "medium"


def test_reference_has_deadlines_compensating_measures_and_sources():
    d = _definition()
    deadlines = {
        lv["code"]: (lv["deadline"]["value"], lv["deadline"]["unit"]) for lv in d["levels"]
    }
    assert deadlines == {
        "critical": (24, "hours"),
        "high": (7, "days"),
        "medium": (4, "weeks"),
        "low": (4, "months"),
    }
    assert all(
        "21" in lv["source"]["clause"] and lv["source"]["table"] == "2" for lv in d["levels"]
    )
    cm = d["compensating_measures"]
    assert cm["source"]["clause"] == "25" and len(cm["items"]) == 5
    assert cm["items"][2]["title"].startswith("Резервирование компонентов")
    assert d["certified_szi"]["source"]["clause"] == "4"
    data = yaml.safe_load(FILE.read_text(encoding="utf-8"))
    assert data["origin"] == "official" and "30.06.2025" in data["source"]["document"]


# ---------- Правила ----------


def test_inputs_are_checked():
    d = _definition()
    good = {"cvss": "8.8", "K": ["K2"], "L": ["L3"], "P": ["P1"], "E": ["E3"], "H": ["H2"]}
    with pytest.raises(InputError, match="показателя P"):
        compute(d, {**good, "P": []})
    with pytest.raises(InputError, match="одно значение"):
        compute(d, {**good, "P": ["P1", "P2"]})
    with pytest.raises(InputError, match="неизвестные значения"):
        compute(d, {**good, "H": ["H99"]})
    with pytest.raises(InputError, match="от 0 до 10"):
        compute(d, {**good, "cvss": "10.5"})
    with pytest.raises(InputError, match="CVSS"):
        compute(d, {**good, "cvss": ""})
    with pytest.raises(InputError, match="неизвестные показатели"):
        compute(d, {**good, "X": ["X1"]})
    # Запятая как десятичный разделитель — допустима.
    assert compute(d, {**good, "cvss": "8,8"}).v == "4.75"


def test_validate_rejects_broken_reference():
    d = copy.deepcopy(_definition())
    _indicator(d, "K")["values"][1]["score"] = 0.8  # межсетевые экраны 0,9 → 0,8
    with pytest.raises(MethodologyError, match=r"Пример 1.*ожидалось"):
        validate(d)

    d = copy.deepcopy(_definition())
    d["levels"][1]["max_inclusive"] = False  # граница 8,0 ничья
    with pytest.raises(MethodologyError, match="ровно к одному"):
        validate(d)

    d = copy.deepcopy(_definition())
    d["levels"][2]["max"] = 4.0  # разрыв между «Средним» и «Высоким»
    with pytest.raises(MethodologyError, match="разрыв"):
        validate(d)

    d = copy.deepcopy(_definition())
    _indicator(d, "H")["values"][1]["code"] = "H1"
    with pytest.raises(MethodologyError, match="повторяется"):
        validate(d)

    d = copy.deepcopy(_definition())
    d["levels"][0]["deadline"]["unit"] = "years"
    with pytest.raises(MethodologyError, match="срок"):
        validate(d)

    d = copy.deepcopy(_definition())
    d["groups"] = d["groups"][:2]
    with pytest.raises(MethodologyError, match="группы"):
        validate(d)


# ---------- Нормативные документы ----------


def test_documents_file_marks_2022_methodology_not_applicable():
    docs = {d["code"]: d for d in parse_documents(yaml.safe_load(DOCS.read_text(encoding="utf-8")))}
    old = docs["fstec-vuln-2022"]
    assert old["status"] == "not_applicable" and old["replaced_by"] == "fstec-vuln-2025"
    assert old["source"]["clause"] == "6"
    assert str(old["issued"]) == "2022-10-28"
    assert docs["fstec-vuln-2025"]["status"] == "active"
    assert str(docs["fstec-117"]["issued"]) == "2025-04-11"


def test_documents_rules():
    base = yaml.safe_load(DOCS.read_text(encoding="utf-8"))
    bad = copy.deepcopy(base)
    bad["documents"][1]["status"] = "active"
    with pytest.raises(DocumentError, match="не применяется"):
        parse_documents(bad)
    bad = copy.deepcopy(base)
    bad["documents"][1]["replaced_by"] = "nope"
    with pytest.raises(DocumentError, match="не найден"):
        parse_documents(bad)
    bad = copy.deepcopy(base)
    bad["documents"][1]["source"] = {}
    with pytest.raises(DocumentError, match="основание"):
        parse_documents(bad)


# ---------- Загрузка ----------


@pytest.fixture
def ref_dir(tmp_path) -> Path:
    shutil.copytree(REFERENCE / "vuln-criticality", tmp_path / "vuln-criticality")
    shutil.copytree(REFERENCE / "normative", tmp_path / "normative")
    (tmp_path / "profiles").mkdir()
    return tmp_path


def test_loader_is_idempotent(session, ref_dir):
    r1 = load_reference(session, ref_dir)
    assert (r1.vuln_added, r1.docs_added) == (1, 7)
    r2 = load_reference(session, ref_dir)
    assert (r2.vuln_added, r2.vuln_updated, r2.vuln_unchanged) == (0, 0, 1)
    assert (r2.docs_added, r2.docs_updated, r2.docs_unchanged) == (0, 0, 7)
    m = session.get(RefVulnMethodology, "fstec-2025")
    assert m.origin == "official" and m.verified_at is None and m.revision == 1
    assert session.get(RefDocument, "fstec-vuln-2022").status == "not_applicable"


def test_loader_updates_changed_file_and_rejects_broken(session, ref_dir):
    load_reference(session, ref_dir)
    path = ref_dir / "vuln-criticality" / "fstec-2025.yaml"
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace('version: "2025-06-30-2"', 'version: "2025-06-30-3"'), encoding="utf-8"
    )
    r = load_reference(session, ref_dir)
    assert r.vuln_updated == 1
    m = session.get(RefVulnMethodology, "fstec-2025")
    assert (m.version, m.revision) == ("2025-06-30-3", 2)
    # Файл, в котором примеры не воспроизводятся, не загружается.
    path.write_text(
        text.replace(
            'score: 0.9, short: "Межсетевой экран"',
            'score: 0.8, short: "Межсетевой экран"',
        ),
        encoding="utf-8",
    )
    with pytest.raises(MethodologyError):
        load_reference(session, ref_dir)


# ---------- API ----------


@pytest.fixture
def env(client, make_user, login, session, ref_dir):
    load_reference(session, ref_dir)
    make_user("admin", "admin", display_name="Администратор")
    make_user("meth", "methodologist", display_name="Иванова А. А.")
    make_user("viewer", "viewer", display_name="Наблюдатель")
    return {u: login(u) for u in ("admin", "meth", "viewer")}


def test_api_shows_methodology_with_reproduced_examples(client, env):
    r = client.get("/refs/vuln-criticality", headers=env["viewer"])
    assert r.status_code == 200
    assert [m["id"] for m in r.json()] == ["fstec-2025"]
    body = client.get("/refs/vuln-criticality/fstec-2025", headers=env["viewer"]).json()
    assert not body["verified"] and body["origin"] == "official"
    assert [
        (e["outcome"]["v"], e["outcome"]["level"]["title"], e["reproduced"])
        for e in body["examples"]
    ] == [
        ("4.75", "Средний", True),
        ("8.47", "Критический", True),
    ]
    assert client.get("/refs/vuln-criticality/nope", headers=env["viewer"]).status_code == 404


def test_api_calculate(client, env):
    inputs = {
        "cvss": "9.8",
        "K": ["K1", "K5"],
        "L": ["L1", "L3"],
        "P": ["P1"],
        "E": ["E2"],
        "H": ["H1"],
    }
    r = client.post(
        "/refs/vuln-criticality/fstec-2025/calculate",
        headers=env["viewer"],
        json={"inputs": inputs},
    )
    assert r.status_code == 200, r.text
    assert r.json()["outcome"]["v"] == "8.47"
    assert r.json()["revision"] == 1
    r = client.post(
        "/refs/vuln-criticality/fstec-2025/calculate",
        headers=env["viewer"],
        json={"inputs": {**inputs, "P": []}},
    )
    assert r.status_code == 422 and "показателя P" in r.json()["detail"]


def test_api_edit_and_verify(client, env, session, make_user, login):
    url = "/refs/vuln-criticality/fstec-2025"
    r = client.post(f"{url}/verify", headers=env["meth"], json={"revision": 1})
    assert r.status_code == 200 and r.json()["verified_by_name"] == "Иванова А. А."
    defn = client.get(url, headers=env["viewer"]).json()["definition"]

    # Правка, ломающая пример приложения, отклоняется.
    broken = copy.deepcopy(defn)
    _indicator(broken, "P")["values"][0]["score"] = 1.0
    r = client.patch(url, headers=env["admin"], json={"definition": broken, "comment": "x"})
    assert r.status_code == 422 and "Пример 1" in r.json()["detail"]

    # Методист не правит; администратор правит — новая ревизия, сверка снята.
    edited = copy.deepcopy(defn)
    _indicator(edited, "H")["values"][-1]["title"] = "Межсайтовый скриптинг (XSS)"
    patch = {"definition": edited, "comment": "уточнено наименование"}
    assert client.patch(url, headers=env["meth"], json=patch).status_code == 403
    r = client.patch(url, headers=env["admin"], json=patch)
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["revision"], body["origin"], body["verified"]) == (2, "local", False)
    assert body["revisions"][0]["comment"] == "уточнено наименование"
    # Без изменений — без новой ревизии.
    assert client.patch(url, headers=env["admin"], json=patch).json()["revision"] == 2

    # Свою правку не сверить.
    make_user("meth2", "methodologist", "admin", display_name="Петров П. П.")
    h2 = login("meth2")
    edited2 = copy.deepcopy(edited)
    _indicator(edited2, "H")["values"][-1]["title"] = "Межсайтовый скриптинг (Cross Site Scripting)"
    assert (
        client.patch(url, headers=h2, json={"definition": edited2, "comment": "вернул"}).status_code
        == 200
    )
    r = client.post(f"{url}/verify", headers=h2, json={"revision": 3})
    assert r.status_code == 403 and "собственную" in r.json()["detail"]
    assert (
        client.post(f"{url}/verify", headers=env["meth"], json={"revision": 2}).status_code == 409
    )
    assert (
        client.post(f"{url}/verify", headers=env["meth"], json={"revision": 3}).status_code == 200
    )

    actions = set(session.scalars(select(AuditRecord.action)))
    assert {"refs.vuln_methodology.update", "refs.vuln_methodology.verify"} <= actions


def test_api_documents(client, env, session):
    r = client.get("/refs/documents", headers=env["viewer"])
    assert r.status_code == 200
    docs = {d["code"]: d for d in r.json()}
    assert docs["fstec-vuln-2022"]["status"] == "not_applicable"
    assert docs["fstec-vuln-2025"]["replaces"] == ["fstec-vuln-2022"]
    assert next(iter(docs)) == "fstec-vuln-2025"

    url = "/refs/documents/fstec-21"
    r = client.patch(url, headers=env["admin"], json={"status": "not_applicable", "comment": "x"})
    assert r.status_code == 422 and "основание" in r.json()["detail"]
    r = client.patch(
        url, headers=env["admin"], json={"url": "https://example.org/21", "comment": "ссылка"}
    )
    assert r.status_code == 200, r.text
    assert (r.json()["revision"], r.json()["origin"]) == (2, "local")
    assert r.json()["revisions"][0]["data"]["url"] is None
    assert (
        client.patch(url, headers=env["meth"], json={"url": "x", "comment": "x"}).status_code == 403
    )
    r = client.post(url + "/verify", headers=env["meth"], json={"revision": 2})
    assert r.status_code == 200 and r.json()["verified"]
    assert "refs.document.update" in set(session.scalars(select(AuditRecord.action)))
