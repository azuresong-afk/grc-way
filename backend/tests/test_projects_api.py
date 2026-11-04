from sqlalchemy import select

from app.db.models import AuditRecord


def _setup(client, make_user, login):
    make_user("meth", "methodologist", display_name="Иванова А. А.")
    make_user("expert", "assessor", display_name="Сидоров С. С.")
    make_user("admin", "admin")
    h = login("meth")
    c = client.post(
        "/customers",
        headers=h,
        json={
            "name": "ГБУ «Центр»",
            "inn": "7701234567",
            "contacts": [{"name": "Кузнецов К. К.", "position": "ИБ"}],
        },
    )
    assert c.status_code == 201, c.text
    p = client.post(
        "/projects",
        headers=h,
        json={
            "customer_id": c.json()["id"],
            "name": "Аттестация ГИС «Учёт»",
            "contract_ref": "Д-17/2026",
            "period_from": "2026-11-01",
            "period_to": "2027-02-28",
        },
    )
    assert p.status_code == 201, p.text
    return h, p.json()


def test_create_project_author_is_member(client, make_user, login, session):
    h, p = _setup(client, make_user, login)
    assert p["client"] == "ГБУ «Центр»"
    assert [m["display_name"] for m in p["members"]] == ["Иванова А. А."]
    assert p["status"] == "active"
    r = client.get("/projects", headers=h)
    assert r.headers["X-Total-Count"] == "1"
    actions = session.scalars(select(AuditRecord.action)).all()
    assert {"customer.create", "project.create"} <= set(actions)


def test_non_member_cannot_see_project(client, make_user, login):
    _, p = _setup(client, make_user, login)
    he = login("expert")
    assert client.get("/projects", headers=he).json() == []
    assert client.get(f"/projects/{p['id']}", headers=he).status_code == 404


def test_members_management(client, make_user, login):
    h, p = _setup(client, make_user, login)
    directory = client.get("/directory/users", headers=h).json()
    names = {u["display_name"]: u["id"] for u in directory}
    assert "Администратор" not in " ".join(names)  # администратор в проекты не входит
    me, expert = names["Иванова А. А."], names["Сидоров С. С."]

    r = client.put(f"/projects/{p['id']}/members", headers=h, json={"user_ids": [me, expert]})
    assert len(r.json()["members"]) == 2
    he = login("expert")
    assert client.get(f"/projects/{p['id']}", headers=he).status_code == 200
    # Эксперт не управляет проектом.
    assert client.patch(f"/projects/{p['id']}", headers=he, json={"name": "x"}).status_code == 403
    # Себя исключить нельзя.
    r = client.put(f"/projects/{p['id']}/members", headers=h, json={"user_ids": [expert]})
    assert r.status_code == 422


def test_admin_has_no_access_to_projects(client, make_user, login):
    _setup(client, make_user, login)
    assert client.get("/projects", headers=login("admin")).status_code == 403


def test_archive_and_period_validation(client, make_user, login):
    h, p = _setup(client, make_user, login)
    r = client.patch(f"/projects/{p['id']}", headers=h, json={"period_to": "2026-01-01"})
    assert r.status_code == 422
    r = client.patch(f"/projects/{p['id']}", headers=h, json={"status": "archived"})
    assert r.json()["status"] == "archived"
    assert client.get("/projects?status=active", headers=h).json() == []


def test_customer_validation(client, make_user, login):
    make_user("meth", "methodologist")
    h = login("meth")
    assert client.post("/customers", headers=h, json={"name": "X", "inn": "123"}).status_code == 422
