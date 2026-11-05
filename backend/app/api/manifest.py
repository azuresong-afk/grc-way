"""Манифест продукта для оболочки «Платформы» (контракт v1.1, п. 5; docs/integration/grc.md).

Отдаётся без авторизации и содержит только метаданные.
"""

from fastapi import APIRouter

from app import __version__
from app.core.config import get_settings

router = APIRouter(tags=["platform"])

# Все роли, включая надбавку: платформа разрешит выдать только роли из этого списка.
ROLES = {
    "admin": "Администратор",
    "methodologist": "Методист",
    "assessor": "Эксперт",
    "approve": "Утверждение (надбавка)",
    "viewer": "Наблюдатель",
}
ADMIN_ROLES = ["admin"]

# Пункты меню — только существующие экраны. Путь — маршрут SPA без base_path.
NAV = [
    {
        "id": "summary",
        "label": "Сводка",
        "path": "summary",
        "icon": "layout-dashboard",
        "perm": "view",
    },
    {"id": "systems", "label": "Объекты", "path": "objects", "icon": "building-2", "perm": "view"},
    {"id": "refs", "label": "Справочники", "path": "refs", "icon": "book-open", "perm": "view"},
]

# Подписки (контракт v1.1, п. 6.4 и 7.3): ключи и проекты платформы, статусы заявок
# «Устранения» (задача 3.4), окончание прогона «Сканера» (только отметка).
SUBSCRIBE = [
    "platform.keys.rotated",
    "platform.project.updated",
    "platform.user.blocked",
    "vm.ticket.status_changed",
    "vm.remediation.verified",
    "scanner.run.finished",
]


@router.get("/manifest")
def manifest() -> dict:
    s = get_settings()
    api = s.api_base.rstrip("/")
    return {
        "id": s.platform_product_id,
        "title": "Аттестация",
        "subtitle": "ФСТЭК №117/21/239",
        "icon": "shield-check",
        "base_path": s.base_path,
        "api_base": s.api_base,
        "version": __version__,
        "roles": ROLES,
        "admin_roles": ADMIN_ROLES,
        "nav": [{**item, "path": s.base_path + item["path"]} for item in NAV],
        "search_url": api + "/search",
        "health_url": api + "/health/ready",
        "summary_url": api + "/summary",
        # webhook — путь внутри нашего API, без префикса /api/grc.
        "events": {"webhook": "/events/platform", "subscribe": SUBSCRIBE},
    }
