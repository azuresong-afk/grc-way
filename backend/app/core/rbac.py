"""Роли и права. Права вычисляются из ролей на каждый запрос (см. deps.require)."""

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    METHODOLOGIST = "methodologist"
    ASSESSOR = "assessor"
    VIEWER = "viewer"
    # Право-надбавка: утверждение класса, адаптации, модели угроз, заключения.
    APPROVE = "approve"


ROLE_TITLES: dict[Role, str] = {
    Role.ADMIN: "Администратор",
    Role.METHODOLOGIST: "Методист",
    Role.ASSESSOR: "Эксперт",
    Role.VIEWER: "Наблюдатель",
    Role.APPROVE: "Утверждающий",
}

# Рабочие роли. Администратор с ними не совмещается (разделение обязанностей).
WORK_ROLES = frozenset({Role.METHODOLOGIST, Role.ASSESSOR, Role.VIEWER, Role.APPROVE})


class Perm(StrEnum):
    USERS_MANAGE = "users.manage"
    REFS_MANAGE = "refs.manage"
    INTEGRATIONS_MANAGE = "integrations.manage"
    AUDIT_VIEW = "audit.view"

    VIEW = "view"
    OBJECTS_EDIT = "objects.edit"
    CLASSIFICATION_EDIT = "classification.edit"
    ADAPTATION_EDIT = "adaptation.edit"
    THREATS_EDIT = "threats.edit"
    DOCUMENTS_EDIT = "documents.edit"
    REFS_VERIFY = "refs.verify"

    ASSESSMENT_EDIT = "assessment.edit"
    EVIDENCE_UPLOAD = "evidence.upload"
    SCANNER_IMPORT = "scanner.import"
    PROTOCOLS_EDIT = "protocols.edit"

    DOCUMENTS_VIEW_APPROVED = "documents.view_approved"
    DOCUMENTS_EXPORT_APPROVED = "documents.export_approved"

    APPROVE = "approve"


_COMMON_VIEW = {Perm.VIEW, Perm.DOCUMENTS_VIEW_APPROVED, Perm.DOCUMENTS_EXPORT_APPROVED}

ROLE_PERMS: dict[Role, frozenset[Perm]] = {
    Role.ADMIN: frozenset(
        {Perm.USERS_MANAGE, Perm.REFS_MANAGE, Perm.INTEGRATIONS_MANAGE, Perm.AUDIT_VIEW}
    ),
    Role.METHODOLOGIST: frozenset(
        {
            *_COMMON_VIEW,
            Perm.OBJECTS_EDIT,
            Perm.CLASSIFICATION_EDIT,
            Perm.ADAPTATION_EDIT,
            Perm.THREATS_EDIT,
            Perm.DOCUMENTS_EDIT,
            Perm.REFS_VERIFY,
        }
    ),
    Role.ASSESSOR: frozenset(
        {
            *_COMMON_VIEW,
            Perm.ASSESSMENT_EDIT,
            Perm.EVIDENCE_UPLOAD,
            Perm.SCANNER_IMPORT,
            Perm.PROTOCOLS_EDIT,
        }
    ),
    Role.VIEWER: frozenset(_COMMON_VIEW),
    # Надбавка: даёт только утверждение; просмотр — от основной роли.
    Role.APPROVE: frozenset({Perm.APPROVE}),
}


def perms_for(roles: set[str]) -> set[Perm]:
    out: set[Perm] = set()
    for r in roles:
        try:
            out |= ROLE_PERMS[Role(r)]
        except ValueError:
            continue  # неизвестная роль из БД не даёт прав
    return out


def roles_problem(roles: set[str]) -> str | None:
    """Ошибка в наборе ролей (на русском) или None."""
    try:
        parsed = {Role(r) for r in roles}
    except ValueError:
        return "Неизвестная роль"
    if not parsed:
        return "Нужна хотя бы одна роль"
    if Role.ADMIN in parsed and parsed & WORK_ROLES:
        return "Администратор не совмещается с рабочими ролями (разделение обязанностей)"
    if parsed == {Role.APPROVE}:
        return "Право «Утверждающий» выдаётся вместе с рабочей ролью"
    return None


class SelfApprovalError(Exception):
    """Попытка утвердить собственную работу."""


def ensure_not_own_work(approver_id: object, *author_ids: object) -> None:
    """Утверждающий не может утвердить запись, которую сам создал или последним менял."""
    if any(a is not None and a == approver_id for a in author_ids):
        raise SelfApprovalError("Нельзя утвердить собственную работу")
