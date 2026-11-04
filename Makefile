# «Аттестация»: частые команды. Требуются docker compose и заполненный .env.
.PHONY: help up down demo logs test lint

help: ## Список команд
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'

up: ## Собрать и запустить стенд (web :18082, api :18002)
	docker compose up -d --build --wait

down: ## Остановить стенд (данные в томах сохраняются)
	docker compose down

demo: up ## Запустить стенд и наполнить демо-данными: ГИС, класс К2, 10 хостов, прогоны «Сканера»
	docker compose exec app python -m app.demo

logs: ## Журналы сервисов
	docker compose logs -f --tail=100

test: ## Тесты бэкенда и фронтенда (локально, без Docker)
	cd backend && pytest -q
	cd frontend && npm test

lint: ## Проверки стиля и типов
	cd backend && ruff check . && ruff format --check .
	cd frontend && npm run typecheck && npm run lint
