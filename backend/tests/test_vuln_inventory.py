"""Задача 2.7: тип компонента и доступность из «Интернета» у хостов, расчёт K, L, P."""

import copy
import shutil
from fractions import Fraction
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select

from app.db.models import AuditRecord
from app.domain.vuln_criticality import InputError, MethodologyError, compute, validate
from app.domain.vuln_inventory import (
    HostData,
    component_types,
    infrastructure,
    readiness,
    share_band,
)
from app.refs.loader import load_reference

REFERENCE = Path(__file__).resolve().parents[2] / "reference"
FILE = REFERENCE / "vuln-criticality" / "fstec-2025.yaml"


def _definition() -> dict:
    return yaml.safe_load(FILE.read_text(encoding="utf-8"))


def _host(address, types=(), internet=None):
    return HostData(
        address=address, hostname=None, component_types=tuple(types), internet_exposed=internet
    )


def test_eight_component_types_from_table_1():
    types = component_types(_definition())
    assert [t["code"] for t in types] == [f"K{i}" for i in range(1, 9)]
    assert [t["short"] for t in types] == [
        "Важные процессы",
        "Межсетевой экран",
        "Сетевое устройство, шлюз",
        "Телеком, управление сетью",
        "Сервер",
        "АРМ",
        "СХД",
        "Другой компонент",
    ]


@pytest.mark.parametrize(
    ("share", "band"),
    [
        (Fraction(0), "L4"),
        (Fraction(999, 100), "L4"),
        (Fraction(10), "L3"),  # «менее 10 %» границу не включает
        (Fraction(4999, 100), "L3"),
        (Fraction(50), "L2"),  # решение «Аттестации»: 50 % — в «50–70 %»
        (Fraction(70), "L2"),  # «более 70 %» границу не включает
        (Fraction(7001, 100), "L1"),
        (Fraction(100), "L1"),
    ],
)
def test_share_bands_boundaries(share, band):
    assert share_band(_definition(), share)["code"] == band


def test_share_is_exact_fraction_not_rounded():
    # 7 из 10 = ровно 70 % → «50–70 %»; 2 из 3 = 66,67 % → тоже L2; 5 из 7 > 70 % → L1.
    d = _definition()
    hosts = [_host(f"10.0.0.{i}", ["K5"], False) for i in range(10)]
    out = infrastructure(d, hosts, [h.address for h in hosts[:7]])
    assert out.by_type[0]["share"] == "70" and out.inputs["L"] == ["L2"]
    seven = hosts[:7]
    out = infrastructure(d, seven, [h.address for h in seven[:5]])
    assert out.inputs["L"] == ["L1"]


def test_example_2_from_inventory():
    """Пример 2 приложения: ВП > 70 %, серверы 50–70 %, АРМ и СХД 10–50 % → I_infr 1,08."""
    d = _definition()
    hosts = (
        # Серверы, обеспечивающие важные процессы: 4 из 5 уязвимы (80 %).
        [_host(f"10.1.0.{i}", ["K1", "K5"], i == 0) for i in range(4)]
        + [_host("10.1.0.9", ["K1"], False)]
        # Прочие серверы: всего серверов 4 + 2 = 6, уязвимы 4 → 66,67 %.
        + [_host(f"10.1.1.{i}", ["K5"], False) for i in range(2)]
        # АРМ: 3 из 10.
        + [_host(f"10.1.2.{i}", ["K6"], False) for i in range(10)]
        # СХД: 1 из 4.
        + [_host(f"10.1.3.{i}", ["K7"], False) for i in range(4)]
        + [_host("10.1.4.1", ["K2"], False)]
    )
    vulnerable = (
        [f"10.1.0.{i}" for i in range(4)] + [f"10.1.2.{i}" for i in range(3)] + ["10.1.3.0"]
    )
    out = infrastructure(d, hosts, vulnerable)
    assert out.missing == []
    assert out.inputs == {"K": ["K1", "K5", "K6", "K7"], "L": ["L1", "L2", "L3"], "P": ["P1"]}
    assert [(r["code"], r["share"], r["band"]) for r in out.by_type] == [
        ("K1", "80", "L1"),
        ("K5", "66.67", "L2"),
        ("K6", "30", "L3"),
        ("K7", "25", "L3"),
    ]
    assert out.exposed == ["10.1.0.0"]
    assert out.i_infr == "1.08"
    # Те же значения дают V примера 2.
    v = compute(d, {"cvss": "9.8", **out.inputs, "E": ["E2"], "H": ["H1"]})
    assert (v.v, v.level["code"]) == ("8.47", "critical")


def test_example_1_from_inventory():
    """Пример 1: межсетевой экран (1 из 4, 25 %), доступен из «Интернета» → I_infr 0,9."""
    d = _definition()
    hosts = [_host("10.0.0.1", ["K2"], True)] + [
        _host(f"10.0.0.{i}", ["K2"], False) for i in range(2, 5)
    ]
    out = infrastructure(d, hosts, ["10.0.0.1"])
    assert out.inputs == {"K": ["K2"], "L": ["L3"], "P": ["P1"]}
    assert out.i_infr == "0.9"


def test_missing_data_is_listed_not_guessed():
    d = _definition()
    hosts = [
        _host("10.0.0.1", ["K5"], None),
        _host("10.0.0.2", [], False),
        _host("10.0.0.3", ["K6"], False),
    ]
    # Уязвим 10.0.0.1: K известен, L — нет (у 10.0.0.2 нет типа), P — не указан.
    out = infrastructure(d, hosts, ["10.0.0.1"])
    assert out.i_infr is None and not out.as_dict()["complete"]
    assert out.inputs == {"K": ["K5"]}
    assert {(m["indicator"], tuple(m["addresses"])) for m in out.missing} == {
        ("L", ("10.0.0.2",)),
        ("P", ("10.0.0.1",)),
    }
    # Уязвим хост без типа: K тоже не определён.
    out = infrastructure(d, hosts, ["10.0.0.2"])
    assert "K" not in out.inputs and out.inputs == {"P": ["P2"]}
    # Хотя бы один уязвимый хост доступен — P определён, даже если про другой не указано.
    hosts[2] = _host("10.0.0.3", ["K6"], True)
    hosts[1] = _host("10.0.0.2", ["K8"], False)
    out = infrastructure(d, hosts, ["10.0.0.1", "10.0.0.3"])
    assert out.inputs["P"] == ["P1"] and out.missing == [] and out.i_infr is not None


def test_infrastructure_input_errors():
    d = _definition()
    with pytest.raises(InputError, match="не выбраны"):
        infrastructure(d, [_host("10.0.0.1", ["K5"], False)], [])
    with pytest.raises(InputError, match="нет в составе"):
        infrastructure(d, [_host("10.0.0.1", ["K5"], False)], ["10.0.0.2"])


def test_readiness_counts_types_and_gaps():
    r = readiness(
        _definition(),
        [
            _host("10.0.0.1", ["K1", "K5"], True),
            _host("10.0.0.2", ["K5"], False),
            _host("10.0.0.3", [], None),
        ],
    )
    assert not r.ready
    assert (r.missing_type, r.missing_internet) == (["10.0.0.3"], ["10.0.0.3"])
    by = {t["code"]: (t["total"], t["internet"]) for t in r.by_type}
    assert by["K1"] == (1, 1) and by["K5"] == (2, 1) and by["K8"] == (0, 0)


def test_validate_checks_inventory_markup():
    base = _definition()
    ind = {i["code"]: i for i in base["indicators"]}
    validate(base)

    d = copy.deepcopy(base)
    {i["code"]: i for i in d["indicators"]}["L"]["values"][1]["share_min_inclusive"] = False
    with pytest.raises(MethodologyError, match="ровно к одному"):
        validate(d)

    d = copy.deepcopy(base)
    {i["code"]: i for i in d["indicators"]}["L"]["values"][2]["share_max"] = 40
    with pytest.raises(MethodologyError, match="разрыв"):
        validate(d)

    d = copy.deepcopy(base)
    {i["code"]: i for i in d["indicators"]}["K"]["values"][0]["short"] = " "
    with pytest.raises(MethodologyError, match="короткой подписи"):
        validate(d)

    d = copy.deepcopy(base)
    {i["code"]: i for i in d["indicators"]}["P"]["values"][1]["internet"] = True
    with pytest.raises(MethodologyError, match="ровно два значения"):
        validate(d)

    d = copy.deepcopy(base)
    {i["code"]: i for i in d["indicators"]}["E"]["inventory"] = "internet"
    with pytest.raises(MethodologyError, match="один источник"):
        validate(d)
    assert ind["K"]["inventory"] == "component_type"


# ---------- API ----------


@pytest.fixture
def env(client, make_user, login, session, tmp_path):
    shutil.copytree(REFERENCE / "vuln-criticality", tmp_path / "vuln-criticality")
    shutil.copytree(REFERENCE / "normative", tmp_path / "normative")
    (tmp_path / "profiles").mkdir()
    load_reference(session, tmp_path)
    session.commit()
    make_user("meth", "methodologist")
    make_user("viewer", "viewer")
    h = login("meth")
    c = client.post("/customers", headers=h, json={"name": "ГБУ «Центр»"}).json()
    p = client.post("/projects", headers=h, json={"customer_id": c["id"], "name": "П"}).json()
    o = client.post(
        f"/projects/{p['id']}/objects", headers=h, json={"kind": "gis", "name": "ГИС"}
    ).json()
    return h, o


def test_api_hosts_keep_inventory_and_validate_types(client, env, session):
    h, o = env
    url = f"/objects/{o['id']}/hosts"
    r = client.put(
        url,
        headers=h,
        json={
            "items": [
                {
                    "address": "10.0.0.1",
                    "component_types": ["K5", "K1", "K5"],
                    "internet_exposed": True,
                },
                {"address": "10.0.0.2"},
            ]
        },
    )
    assert r.status_code == 200, r.text
    by = {x["address"]: x for x in r.json()}
    assert by["10.0.0.1"]["component_types"] == ["K1", "K5"]
    assert by["10.0.0.1"]["internet_exposed"] is True
    assert by["10.0.0.2"]["component_types"] is None and by["10.0.0.2"]["internet_exposed"] is None

    # Клиент, который не передаёт поля инвентаризации, их не стирает.
    r = client.put(
        url,
        headers=h,
        json={"items": [{"address": "10.0.0.1", "role": "СУБД"}, {"address": "10.0.0.2"}]},
    )
    by = {x["address"]: x for x in r.json()}
    assert by["10.0.0.1"]["component_types"] == ["K1", "K5"] and by["10.0.0.1"]["role"] == "СУБД"

    # Явный null — сброс.
    r = client.put(
        url,
        headers=h,
        json={"items": [{"address": "10.0.0.1", "component_types": [], "internet_exposed": None}]},
    )
    assert r.json()[0]["component_types"] is None and r.json()[0]["internet_exposed"] is None
    changes = session.scalars(select(AuditRecord).where(AuditRecord.action == "object.hosts")).all()
    assert changes[-1].details["changed"]["addresses"] == ["10.0.0.1"]

    bad = client.put(
        url, headers=h, json={"items": [{"address": "10.0.0.1", "component_types": ["K9"]}]}
    )
    assert bad.status_code == 422 and "K9" in bad.json()["detail"]


def test_api_inventory_and_infr(client, env, login):
    h, o = env
    client.patch(f"/objects/{o['id']}", headers=h, json={"internet": False})
    client.put(
        f"/objects/{o['id']}/hosts",
        headers=h,
        json={
            "items": [
                {"address": "10.0.0.1", "component_types": ["K2"], "internet_exposed": True},
                {"address": "10.0.0.2", "component_types": ["K2"], "internet_exposed": False},
                {"address": "10.0.0.3", "component_types": ["K6"]},
            ]
        },
    )
    v = login("viewer")
    inv = client.get(f"/objects/{o['id']}/inventory", headers=v)
    # Наблюдатель не участник проекта — объект не раскрывается.
    assert inv.status_code == 404
    inv = client.get(f"/objects/{o['id']}/inventory", headers=h).json()
    assert inv["hosts_total"] == 3 and not inv["ready"]
    assert inv["missing_type"] == [] and inv["missing_internet"] == ["10.0.0.3"]
    assert inv["internet_conflict"] == ["10.0.0.1"]
    assert inv["methodology"]["id"] == "fstec-2025"
    assert {t["code"]: t["total"] for t in inv["types"]}["K2"] == 2

    r = client.post(
        f"/objects/{o['id']}/inventory/infr", headers=h, json={"addresses": ["10.0.0.1"]}
    )
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["complete"] and out["inputs"] == {"K": ["K2"], "L": ["L2"], "P": ["P1"]}
    # 0,5 × 0,9 + 0,2 × 0,8 + 0,3 × 1,1 = 0,94
    assert out["i_infr"] == "0.94"
    assert [row["indicator"] for row in out["trace"]] == ["K", "L", "P"]

    r = client.post(
        f"/objects/{o['id']}/inventory/infr", headers=h, json={"addresses": ["10.0.0.3"]}
    ).json()
    assert not r["complete"] and r["missing"][0]["indicator"] == "P"
    bad = client.post(
        f"/objects/{o['id']}/inventory/infr", headers=h, json={"addresses": ["10.9.9.9"]}
    )
    assert bad.status_code == 422

    types = client.get("/refs/component-types", headers=h).json()
    assert len(types) == 8 and types[1]["short"] == "Межсетевой экран"
