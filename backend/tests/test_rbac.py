import uuid

import pytest
from sqlalchemy import select

from app.core.rbac import (
    Perm,
    Role,
    SelfApprovalError,
    ensure_not_own_work,
    perms_for,
    roles_problem,
)
from app.db.models import AuditRecord


def test_admin_has_no_work_permissions():
    perms = perms_for({"admin"})
    assert Perm.USERS_MANAGE in perms
    assert Perm.VIEW not in perms
    assert Perm.ASSESSMENT_EDIT not in perms
    assert Perm.APPROVE not in perms


def test_approve_is_an_addon():
    assert perms_for({"approve"}) == {Perm.APPROVE}
    assert Perm.APPROVE in perms_for({"methodologist", "approve"})


def test_unknown_role_gives_nothing():
    assert perms_for({"root"}) == set()


@pytest.mark.parametrize(
    ("roles", "ok"),
    [
        ({"admin"}, True),
        ({"methodologist", "approve"}, True),
        ({"assessor", "viewer"}, True),
        ({"admin", "assessor"}, False),
        ({"admin", "approve"}, False),
        ({"approve"}, False),
        (set(), False),
        ({"superuser"}, False),
    ],
)
def test_roles_validation(roles, ok):
    assert (roles_problem(roles) is None) is ok


def test_self_approval_is_forbidden():
    me, other = uuid.uuid4(), uuid.uuid4()
    ensure_not_own_work(me, other, None)
    with pytest.raises(SelfApprovalError):
        ensure_not_own_work(me, other, me)


def test_every_role_value_has_perms():
    assert all(perms_for({r.value}) for r in Role)


def test_forbidden_request_is_audited(client, make_user, login, session):
    make_user("viewer1", "viewer")
    r = client.get("/users", headers=login("viewer1"))
    assert r.status_code == 403
    assert r.json()["detail"] == "Недостаточно прав"
    rec = session.scalars(select(AuditRecord).where(AuditRecord.action == "access.denied")).one()
    assert rec.result == "denied"
    assert rec.details["missing"] == ["users.manage"]
