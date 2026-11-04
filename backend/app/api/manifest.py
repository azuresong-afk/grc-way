"""Манифест продукта для оболочки «Платформы» (контракт платформы v1, п. 5).

Отдаётся без авторизации и содержит только метаданные.
"""

from fastapi import APIRouter

from app import __version__
from app.core.config import get_settings

router = APIRouter(tags=["platform"])

ROLES = {
    "methodologist": "Методист",
    "assessor": "Эксперт",
    "viewer": "Наблюдатель",
    "admin": "Администратор",
}

# Пункты меню появляются в манифесте вместе с экранами, а не заранее.
NAV = [
    {
        "id": "summary",
        "label": "Сводка",
        "path": "summary",
        "icon": "layout-dashboard",
        "perm": "view",
    },
]


@router.get("/manifest")
def manifest() -> dict:
    s = get_settings()
    return {
        "id": "grc",
        "title": "Аттестация",
        "subtitle": "соответствие ФСТЭК",
        "icon": "shield-check",
        "base_path": s.base_path,
        "api_base": s.api_base,
        "version": __version__,
        "roles": ROLES,
        "nav": [{**item, "path": s.base_path + item["path"]} for item in NAV],
        "search_url": s.api_base + "search",
        "health_url": s.api_base + "health/ready",
    }
