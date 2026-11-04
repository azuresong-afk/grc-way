# «Аттестация» (`grc`)

Рабочее место специалиста по защите информации для аттестации информационных систем по требованиям ФСТЭК России (приказы №117, №21, №239): классификация, набор мер и адаптация, оценка реализации (автоматически по результатам «Сканера» и вручную), модель угроз по Методике 2021, комплект документов.

- ТЗ: [docs/brief.md](docs/brief.md)
- Архитектура и план работ: [docs/roadmap.md](docs/roadmap.md)

## Запуск

```sh
cp .env.example .env
# заполнить POSTGRES_PASSWORD и GRC_SECRET_KEY (openssl rand -hex 32)
docker compose up --build
```

Интерфейс — http://localhost:18082, API — http://127.0.0.1:18002 (через интерфейс — `/api/*`). Проверка: `curl localhost:18082/api/health/ready` → `{"status":"ok","db":"ok"}`.

## Разработка

```sh
# API (SQLite, режим разработки)
cd backend && python3.12 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
GRC_DEV_MODE=1 alembic upgrade head && GRC_DEV_MODE=1 uvicorn app.main:create_app --factory --port 18002
pytest && ruff check . && ruff format --check .

# Интерфейс (Vite проксирует /api на :18002)
cd frontend && npm ci && npm run dev
npm run typecheck && npm run lint && npm test
```

| часть | стек |
|---|---|
| `backend/` | Python 3.12, FastAPI, SQLAlchemy 2, Alembic (миграции `0001_…`, тест-страж цепочки), PostgreSQL 16 |
| `frontend/` | React 18, TypeScript strict, Vite 5, стили и классы «Сканера» (`src/tokens.css`, `src/styles.css`) |
