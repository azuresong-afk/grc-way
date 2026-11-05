"""Проверка JWT «Платформы» (контракт v1.1, п. 2; docs/integration/README.md, п. 2).

Порядок проверок и коды ответов — как в эталоне платформы
(`dev/fakeproduct/auth.py`), проверено векторами `docs/integration/vectors/jwt.json`:

1. `Authorization: Bearer` есть — иначе 401 `not_authenticated`;
2. `alg` ровно `EdDSA`; 3. `kid` найден в JWKS (неизвестный — перечитать сразу,
   не чаще раза в 30 с; кэш 10 мин); 4. подпись; 5. `iss`, `exp`/`iat` (сдвиг 60 с),
   свой id в `aud` — иначе 401 `invalid_token`;
6. непустые `products.<свой id>` — иначе 403 `no_product_roles`.

Доступ к проекту (403 `no_project_access`) проверяется там, где известен проект.
Отозванные ключи (`platform.keys.rotated` с непустым `revoked`) не принимаются,
даже если старая копия JWKS ещё в памяти.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt

JWKS_TTL = 600
JWKS_MIN_REFETCH = 30
LEEWAY = 60
ISSUER = "platform"


class PlatformAuthError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


class JwksCache:
    def __init__(
        self,
        url: str,
        fetch: Callable[[], dict] | None = None,
        clock: Callable[[], float] = time.monotonic,
        timeout: float = 5.0,
        verify: bool | str = True,
    ) -> None:
        self.url = url
        self._fetch = fetch or self._http_fetch
        self._clock = clock
        self._timeout = timeout
        self._verify = verify
        self._keys: dict[str, dict] = {}
        self._fetched_at: float | None = None
        self._revoked: set[str] = set()
        self._lock = threading.Lock()

    def _http_fetch(self) -> dict:
        if not self.url:
            raise ValueError("PLATFORM_JWKS_URL не задан")
        r = httpx.get(self.url, timeout=self._timeout, verify=self._verify)
        r.raise_for_status()
        return r.json()

    def _refresh(self) -> None:
        data = self._fetch()
        keys = data.get("keys", [])
        self._keys = {k["kid"]: k for k in keys if isinstance(k, dict) and k.get("kid")}
        self._fetched_at = self._clock()

    def get(self, kid: str) -> dict | None:
        if not kid or kid in self._revoked:
            return None
        with self._lock:
            age = None if self._fetched_at is None else self._clock() - self._fetched_at
            stale = age is None or age > JWKS_TTL
            unknown = kid not in self._keys and (age is None or age > JWKS_MIN_REFETCH)
            if stale or unknown:
                try:
                    self._refresh()
                except (httpx.HTTPError, ValueError, KeyError, TypeError):
                    pass  # остаёмся на старой копии; неизвестный kid → 401
            return self._keys.get(kid)

    def revoke(self, kids: list[str]) -> None:
        """Срочная смена ключей: сбросить кэш сразу и больше не принимать эти kid."""
        with self._lock:
            self._revoked.update(k for k in kids if k)
            for k in kids:
                self._keys.pop(k, None)
            self._fetched_at = None

    def invalidate(self) -> None:
        with self._lock:
            self._fetched_at = None


@dataclass
class Claims:
    sub: str
    username: str
    name: str
    typ: str
    roles: list[str]
    projects: list[str]
    raw: dict[str, Any] = field(default_factory=dict)


def bearer(header: str | None) -> str:
    if not header or not header.lower().startswith("bearer "):
        raise PlatformAuthError(401, "not_authenticated")
    token = header[7:].strip()
    if not token:
        raise PlatformAuthError(401, "not_authenticated")
    return token


def verify_token(token: str, product_id: str, jwks: JwksCache) -> Claims:
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "EdDSA":
            raise PlatformAuthError(401, "invalid_token")
        jwk = jwks.get(str(header.get("kid") or ""))
        if jwk is None:
            raise PlatformAuthError(401, "invalid_token")
        claims = jwt.decode(
            token,
            jwt.PyJWK(jwk).key,
            algorithms=["EdDSA"],
            audience=product_id,
            issuer=ISSUER,
            leeway=LEEWAY,
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
    except PlatformAuthError:
        raise
    except (jwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
        raise PlatformAuthError(401, "invalid_token") from exc
    products = claims.get("products")
    roles = products.get(product_id) if isinstance(products, dict) else None
    if not isinstance(roles, list) or not roles:
        raise PlatformAuthError(403, "no_product_roles")
    projects = claims.get("projects")
    return Claims(
        sub=str(claims["sub"]),
        username=str(claims.get("preferred_username") or ""),
        name=str(claims.get("name") or ""),
        typ="service" if claims.get("typ") == "service" else "user",
        roles=[str(r) for r in roles],
        projects=[str(p) for p in projects] if isinstance(projects, list) else [],
        raw=claims,
    )
