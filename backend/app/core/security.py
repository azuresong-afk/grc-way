"""Пароли (scrypt), токены доступа (JWT HS256) и пауза после неудачных входов.

Формат хэша и политика паролей совпадают со «Сканером». В токен кладётся только
идентификатор пользователя: роли читаются из БД на каждый запрос, поэтому отзыв
роли или блокировка действуют сразу.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
import uuid
from collections.abc import Callable

import jwt

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1
MIN_PASSWORD_LEN = 12
_AUDIENCE = "grc"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(
        password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        algo, n, r, p, salt, dk = stored.split("$")
        if algo != "scrypt":
            return False
        got = hashlib.scrypt(
            password.encode(),
            salt=bytes.fromhex(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(dk)),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got.hex(), dk)


# Хэш-пустышка: проверка для несуществующего пользователя занимает то же время.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def password_problem(password: str) -> str | None:
    """Текст ошибки на русском или None, если пароль подходит."""
    if len(password) < MIN_PASSWORD_LEN:
        return f"Пароль должен быть не короче {MIN_PASSWORD_LEN} символов"
    return None


class TokenSigner:
    def __init__(self, secret: str, ttl_seconds: int, clock: Callable[[], float] = time.time):
        if len(secret) < 32:
            raise ValueError("секрет подписи токенов короче 32 символов")
        self._key = secret
        self.ttl = ttl_seconds
        self._clock = clock

    def issue(self, user_id: uuid.UUID) -> str:
        now = int(self._clock())
        payload = {
            "sub": str(user_id),
            "aud": _AUDIENCE,
            "iat": now,
            "exp": now + self.ttl,
            "jti": str(uuid.uuid4()),
        }
        return jwt.encode(payload, self._key, algorithm="HS256")

    def verify(self, token: str) -> uuid.UUID | None:
        """Идентификатор пользователя или None (подпись неверна, токен истёк, мусор)."""
        try:
            payload = jwt.decode(
                token,
                self._key,
                algorithms=["HS256"],
                audience=_AUDIENCE,
                # Срок проверяем сами по своим часам (в тестах — подменённым).
                options={
                    "require": ["sub", "exp", "iat"],
                    "verify_exp": False,
                    "verify_iat": False,
                },
                leeway=0,
            )
            if int(payload["exp"]) < self._clock():
                return None
            return uuid.UUID(payload["sub"])
        except (jwt.PyJWTError, ValueError, KeyError, TypeError):
            return None


class LoginThrottle:
    """Пауза после N неудачных входов подряд для одного имени (в памяти процесса)."""

    def __init__(
        self, max_failures: int, lockout_seconds: int, clock: Callable[[], float] = time.monotonic
    ):
        self.max_failures = max_failures
        self.lockout = lockout_seconds
        self._clock = clock
        self._state: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def locked(self, username: str) -> bool:
        with self._lock:
            _, until = self._state.get(username, (0, 0.0))
            return until > self._clock()

    def failure(self, username: str) -> None:
        with self._lock:
            n, _ = self._state.get(username, (0, 0.0))
            n += 1
            until = self._clock() + self.lockout if n >= self.max_failures else 0.0
            self._state[username] = (0 if until else n, until)

    def success(self, username: str) -> None:
        with self._lock:
            self._state.pop(username, None)
