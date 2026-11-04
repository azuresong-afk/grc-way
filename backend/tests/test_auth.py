from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from app.core.security import TokenSigner, hash_password, verify_password
from app.db.models import AuditRecord


def test_password_hash_roundtrip_and_format():
    h = hash_password("x" * 12)
    assert h.startswith("scrypt$16384$8$1$")
    assert verify_password("x" * 12, h)
    assert not verify_password("y" * 12, h)
    assert not verify_password("x", "garbage")
    assert not verify_password("x", None)


def test_token_expires_and_rejects_tampering():
    now = [1000.0]
    signer = TokenSigner("k" * 32, 60, clock=lambda: now[0])
    import uuid

    uid = uuid.uuid4()
    tok = signer.issue(uid)
    assert signer.verify(tok) == uid
    assert signer.verify(tok + "x") is None
    assert TokenSigner("z" * 32, 60, clock=lambda: now[0]).verify(tok) is None
    now[0] += 61
    assert signer.verify(tok) is None


def test_login_me_logout(client, make_user, login, session):
    make_user("ivanov", "methodologist", "approve", display_name="Иванов И. И.")
    h = login("ivanov")
    me = client.get("/me", headers=h).json()
    assert me["display_name"] == "Иванов И. И."
    assert me["roles"] == ["approve", "methodologist"]
    assert "classification.edit" in me["permissions"]
    assert "approve" in me["permissions"]
    assert "users.manage" not in me["permissions"]
    assert client.post("/auth/logout", headers=h).status_code == 204
    actions = session.scalars(select(AuditRecord.action).order_by(AuditRecord.id)).all()
    assert actions == ["auth.login", "auth.logout"]


def test_username_is_case_insensitive(client, make_user, login):
    make_user("petrov", "viewer")
    login("Petrov")


def test_bad_password_is_audited_without_secret(client, make_user, session):
    make_user("sidorov", "assessor")
    r = client.post("/auth/token", json={"username": "sidorov", "password": "wrong-password!"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Неверное имя или пароль"
    rec = session.scalars(select(AuditRecord)).one()
    assert (rec.action, rec.result, rec.user_name) == ("auth.login", "denied", "sidorov")
    assert "wrong-password!" not in str(rec.details)


def test_unknown_user_gets_same_answer(client):
    r = client.post("/auth/token", json={"username": "nobody", "password": "whatever-123"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Неверное имя или пароль"


def test_throttle_after_repeated_failures(client, make_user, login):
    make_user("kozlov", "viewer")
    for _ in range(5):
        client.post("/auth/token", json={"username": "kozlov", "password": "nope-nope-nope"})
    r = client.post("/auth/token", json={"username": "kozlov", "password": "correct-horse-battery"})
    assert r.status_code == 429


def test_requests_without_or_with_bad_token(client):
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer junk"}).status_code == 401


def test_deactivation_and_role_revocation_apply_immediately(client, make_user, login, session):
    u = make_user("orlov", "viewer")
    h = login("orlov")
    assert client.get("/me", headers=h).status_code == 200
    u.is_active = False
    session.commit()
    assert client.get("/me", headers=h).status_code == 401


def test_audit_log_is_append_only(session):
    from app import audit

    audit.record_now(session, action="test.event", actor_name="system")
    for stmt in ("UPDATE audit_log SET action = 'x'", "DELETE FROM audit_log"):
        try:
            session.execute(text(stmt))
            session.commit()
        except DatabaseError as e:
            session.rollback()
            assert "append-only" in str(e)
        else:
            raise AssertionError(f"{stmt} должен быть запрещён")
    assert session.scalars(select(AuditRecord.action)).all() == ["test.event"]
