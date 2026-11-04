#!/bin/sh
# Порядок запуска: проверка секретов → миграции → первый администратор → API.
set -eu

fail() { echo "ошибка запуска: $*" >&2; exit 1; }

[ -n "${POSTGRES_PASSWORD:-}" ] || fail "не задан POSTGRES_PASSWORD"
key="${GRC_SECRET_KEY:-}"
[ "${#key}" -ge 32 ] || fail "GRC_SECRET_KEY не задан или короче 32 символов"

if [ -z "${GRC_DATABASE_URL:-}" ]; then
  GRC_DATABASE_URL="postgresql+psycopg://${POSTGRES_USER:-grc}:${POSTGRES_PASSWORD}@${POSTGRES_HOST:-db}:5432/${POSTGRES_DB:-grc}"
  export GRC_DATABASE_URL
fi

echo "миграции БД…"
alembic upgrade head

python -m app.bootstrap

exec "$@"
