#!/bin/sh
# Порядок запуска: проверка секретов → миграции → первый администратор →
# справочники → API.
set -eu

fail() { echo "ошибка запуска: $*" >&2; exit 1; }

key="${GRC_SECRET_KEY:-}"
[ "${#key}" -ge 32 ] || fail "GRC_SECRET_KEY не задан или короче 32 символов"

# В комплекте «Платформы» строка подключения приходит готовой (DATABASE_URL).
if [ -z "${GRC_DATABASE_URL:-}" ] && [ -n "${DATABASE_URL:-}" ]; then
  GRC_DATABASE_URL="$DATABASE_URL"
  export GRC_DATABASE_URL
fi
if [ -z "${GRC_DATABASE_URL:-}" ]; then
  [ -n "${POSTGRES_PASSWORD:-}" ] || fail "не задан POSTGRES_PASSWORD"
  GRC_DATABASE_URL="postgresql+psycopg://${POSTGRES_USER:-grc}:${POSTGRES_PASSWORD}@${POSTGRES_HOST:-db}:5432/${POSTGRES_DB:-grc}"
  export GRC_DATABASE_URL
fi

echo "миграции БД…"
alembic upgrade head

# В режиме платформы своих паролей нет: пользователи — теневые записи по токену.
mode="${GRC_AUTH_MODE:-${AUTH_MODE:-local}}"
if [ "$mode" != "platform" ]; then
  python -m app.bootstrap
fi

# Справочники из reference/: добавляет новое, не затирает правки из интерфейса.
python -m app.refs.loader

exec "$@"
