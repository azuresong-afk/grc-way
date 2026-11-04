from sqlalchemy import select

from app.bootstrap import ensure_admin
from app.db.models import AuditRecord, User


def test_admin_creates_lists_and_updates_users(client, make_user, login, session):
    make_user("admin", "admin")
    h = login("admin")

    r = client.post(
        "/users",
        headers=h,
        json={
            "username": "Ivanova",
            "display_name": "Иванова А. А.",
            "password": "long-enough-pass",
            "roles": ["assessor"],
        },
    )
    assert r.status_code == 201, r.text
    uid = r.json()["id"]
    assert r.json()["username"] == "ivanova"

    r = client.get("/users?limit=1", headers=h)
    assert r.headers["X-Total-Count"] == "2"
    assert len(r.json()) == 1

    r = client.patch(f"/users/{uid}", headers=h, json={"roles": ["assessor", "approve"]})
    assert r.json()["roles"] == ["approve", "assessor"]

    actions = session.scalars(select(AuditRecord.action).order_by(AuditRecord.id)).all()
    assert actions[-2:] == ["user.create", "user.update"]
    details = session.scalars(select(AuditRecord.details).order_by(AuditRecord.id)).all()
    assert all("long-enough-pass" not in str(d) for d in details)


def test_user_validation(client, make_user, login):
    me = make_user("admin", "admin")
    h = login("admin")
    base = {"username": "x1", "display_name": "X", "password": "long-enough-pass"}
    assert (
        client.post("/users", headers=h, json={**base, "roles": ["admin", "assessor"]}).status_code
        == 422
    )
    assert (
        client.post(
            "/users", headers=h, json={**base, "password": "short", "roles": ["viewer"]}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/users", headers=h, json={**base, "username": "admin", "roles": ["viewer"]}
        ).status_code
        == 409
    )
    assert client.patch(f"/users/{me.id}", headers=h, json={"is_active": False}).status_code == 422
    assert client.patch(f"/users/{me.id}", headers=h, json={"roles": ["viewer"]}).status_code == 422


def test_audit_list_and_export(client, make_user, login):
    make_user("admin", "admin")
    h = login("admin")
    r = client.get("/audit?action=auth", headers=h)
    assert r.status_code == 200
    assert r.headers["X-Total-Count"] == "1"
    assert r.json()[0]["action"] == "auth.login"
    r = client.get("/audit/export", headers=h)
    assert r.headers["content-type"].startswith("text/csv")
    assert "auth.login" in r.text


def test_audit_is_admin_only(client, make_user, login):
    make_user("m", "methodologist")
    assert client.get("/audit", headers=login("m")).status_code == 403


def test_bootstrap_admin_once(session):
    assert "создан" in ensure_admin(session, "Admin", "long-enough-pass")
    assert "уже есть" in ensure_admin(session, "other", "long-enough-pass")
    u = session.scalars(select(User)).one()
    assert (u.username, u.roles) == ("admin", {"admin"})
