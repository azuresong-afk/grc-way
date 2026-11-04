# «Аттестация»: частые команды. Требуются docker compose и заполненный .env.
.PHONY: help up down demo logs backup test lint

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

# Каталог резервных копий; восстановление — docs/INSTALL.md, раздел «Восстановление».
BACKUP_DIR ?= backup
STAMP := $(shell date +%Y%m%d-%H%M%S)

backup: ## Резервная копия: дамп БД и файлы доказательств в $(BACKUP_DIR)/
	@mkdir -p $(BACKUP_DIR)
	docker compose exec -T db sh -c 'pg_dump -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" -Fc' > $(BACKUP_DIR)/grc-$(STAMP).dump
	docker compose exec -T app tar czf - -C /data evidence > $(BACKUP_DIR)/grc-$(STAMP)-evidence.tgz
	@ls -l $(BACKUP_DIR)/grc-$(STAMP)*

test: ## Тесты бэкенда и фронтенда (локально, без Docker)
	cd backend && pytest -q
	cd frontend && npm test

lint: ## Проверки стиля и типов
	cd backend && ruff check . && ruff format --check .
	cd frontend && npm run typecheck && npm run lint
