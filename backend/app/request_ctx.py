"""Метод текущего HTTP-запроса — чтобы общие помощники знали, читает запрос или меняет."""

from __future__ import annotations

from contextvars import ContextVar

request_method: ContextVar[str] = ContextVar("request_method", default="GET")

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def is_write() -> bool:
    return request_method.get() not in READ_METHODS
