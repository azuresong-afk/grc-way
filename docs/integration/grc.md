# «Аттестация» (`grc`): что сделать для работы в «Платформе»

Общие правила (проверка токена, проекты, события, фронтенд, тестовые векторы) — в [`README.md`](README.md); здесь только то, что относится к «Аттестации». Номера пунктов — пункты [контракта v1.1](../contract-v1.1.md).

«Аттестация» ведёт объекты (ГИС, ИСПДн, ЗО КИИ), меры по приказам ФСТЭК №117/21/239 и документы. От «Сканера» она может брать результаты проверок соответствия, но сама в шину отдаёт только ход аттестации и аудит.

## Сводка задач

| # | Задача | Где проверяется |
|---|---|---|
| 1 | `AUTH_MODE=platform`: проверка JWT по JWKS, теневые пользователи, 401/403 | векторы `vectors/jwt.json` |
| 2 | `platform_project_id` у проектов, запрет создания проектов в режиме `platform` | тесты продукта |
| 3 | `GET /manifest` с ролями `admin, methodologist, assessor, approve, viewer` | экран «Продукты» платформы |
| 4 | `GET /summary`, `GET /search` | Главная и Ctrl+K |
| 5 | Outbox и события `grc.assessment.updated`, `audit.recorded`; «документ ждёт утверждения» — с `notify` | `vectors/hmac.json`, `vectors/events.json` |
| 6 | Фронтенд: `VITE_BASE=/grc/`, `VITE_API_BASE=/api/grc`, 401/403, выход отовсюду (`platform.logout`), `@platform/ui`, угловатые токены | стенд платформы |
| 7 | (необязательно) подписка на `scanner.run.finished` и чтение соответствия из «Сканера» сервисным токеном | `vectors/hmac.json` |
| 8 | Комплект: переменные п. 12 (`DATABASE_URL`, `PLATFORM_*`), миграции и восстановление без прав суперпользователя | README, п. 1–1.1 |

## 1. Вход, права, проекты

Как в README, п. 2–3: роли — из `products.grc`, теневые пользователи по `sub`, теневые проекты по `platform_project_id`, архивный проект — `409 project_archived` на изменения.

| Роль | Смысл |
|---|---|
| `admin` | администрирование продукта, без рабочих операций |
| `methodologist` | методист: профили мер, сопоставление «мера → проверка», шаблоны документов |
| `assessor` | аттестатор: оценка мер на объекте, подготовка документов |
| `approve` | надбавка: утверждение документов |
| `viewer` | только просмотр |

Разделение обязанностей: автор документа не утверждает его сам, даже если у него есть `approve`. Это проверка «Аттестации»; платформа лишь подсвечивает совмещение ролей в матрице доступа.

## 2. Манифест

```json
{"id":"grc","title":"Аттестация","subtitle":"ФСТЭК №117/21/239","icon":"shield-check",
 "base_path":"/grc/","api_base":"/api/grc/","version":"1.0.0",
 "roles":{"admin":"Администратор","methodologist":"Методист","assessor":"Аттестатор",
          "approve":"Утверждение (надбавка)","viewer":"Наблюдатель"},
 "admin_roles":["admin"],
 "nav":[{"id":"systems","label":"Объекты","path":"/grc/systems","icon":"building-2","perm":"view"},
        {"id":"documents","label":"Документы","path":"/grc/documents","icon":"file-text","perm":"view"}],
 "search_url":"/api/grc/search","health_url":"/api/grc/health/ready","summary_url":"/api/grc/summary",
 "events":{"webhook":"/events/platform","subscribe":["scanner.run.finished","platform.keys.rotated","platform.project.updated"]}}
```

Подписка на `scanner.run.finished` нужна, только если используются результаты «Сканера» (п. 5); на события платформы — всем (README, п. 7.3).

## 3. Сводка и поиск

```json
{"product":"grc","project_id":"3e2a8c1f-5b7d-4f9e-a1c3-6d8b0e2f4a61","generated_at":"2026-11-04T16:54:52Z",
 "link":"/grc/?project=3e2a8c1f-5b7d-4f9e-a1c3-6d8b0e2f4a61",
 "data":{"systems":3,"measures_percent":64,"documents":{"ready":9,"total":14}}}
```

- `systems` — объекты проекта; `measures_percent` — доля реализованных мер по всем объектам проекта, целое 0–100 (организационные меры без оценки в знаменатель не входят — как в профилях «Сканера»); `documents` — готовые (утверждённые) и все документы комплекта.

Поиск: `kind` — `system`, `measure`, `document`. По названию объекта, коду меры (`УПД.1`, `ИАФ.3`), названию документа. Пример ссылки: `/grc/systems/7/measures/УПД.1?project=<uuid>` (кириллицу в пути кодируйте `encodeURIComponent`).

## 4. События

| Тип | Когда | `subject` | `notify` |
|---|---|---|---|
| `grc.assessment.updated` | изменился процент реализации мер или статус аттестации объекта | `system/<id>` | — |
| `grc.document.approval_requested` | документ отправлен на утверждение | `document/<id>` | пользователям с ролью `approve` |
| `audit.recorded` | каждая запись журнала аудита | `audit/<id>` | — |

`grc.assessment.updated` (п. 6.2):

```json
{"system_id":"7","title":"ГИС «Учёт»","percent":64,"status":"in_progress"}
```

Шлите не на каждую отметку меры, а не чаще раза в минуту на объект (последнее значение) — платформе нужна актуальная картина, а не поток правок.

**Документ ждёт утверждения.** Контракт требует уведомить пользователей с ролью `approve`. Для этого в контракт v1.1 (п. 6.2) добавлен тип `grc.document.approval_requested`:

```json
{"id":"…","type":"grc.document.approval_requested","source":"grc","time":"2026-11-04T16:54:52Z",
 "project_id":"3e2a8c1f-5b7d-4f9e-a1c3-6d8b0e2f4a61","subject":"document/31",
 "data":{"document_id":"31","title":"Акт классификации ГИС «Учёт»","system_id":"7",
         "author_sub":"6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b"},
 "notify":{"users":["<sub утверждающего>","…"],"title":"Документ ждёт утверждения: Акт классификации",
           "link":"/grc/documents/31?project=3e2a8c1f-5b7d-4f9e-a1c3-6d8b0e2f4a61"}}
```

Адресатов «Аттестация» выбирает сама: теневые пользователи, у которых в последнем токене была роль `approve` и есть доступ к проекту, кроме автора. Платформа адресатов по типу события не угадывает.

## 5. Связь со «Сканером» (необязательно)

Если «Аттестация» использует результаты проверок соответствия «Сканера» (`GET /runs/{id}/compliance?profile=fstec-117&level=К2`):

- вызовы — сервисным токеном (`POST {PLATFORM_URL}/auth/token`, как в [`vm.md`](vm.md), п. 4) учётной записи с ролью `auditor` в «Сканере»; переменные `PLATFORM_SCANNER_CLIENT_ID`, `PLATFORM_SCANNER_CLIENT_SECRET`;
- подписка на `scanner.run.finished` — сигнал перечитать результат прогона;
- сопоставление «мера → техническая проверка» в «Сканере» ещё не сверено методистом: результат «Сканера» — подсказка аттестатору, а не автоматическая отметка меры.

## 6. Фронтенд

`VITE_BASE=/grc/ VITE_API_BASE=/api/grc VITE_PLATFORM=1`; 401/403/выход — README, п. 8, включая «выход отовсюду»: вкладка продукта слушает `storage` по ключу `platform.logout` и уходит на `/login` (с `@platform/ui` — `AuthProvider`).

## 7. Проверка

1. Тесты: все случаи `vectors/jwt.json` с `product: "grc"` (в том числе `user_all_projects` → `200` с ролью `methodologist` в обоих проектах), все `vectors/hmac.json`.
2. Регресс `AUTH_MODE=local`.
3. Стенд платформы:
   - отметка меры → в течение минуты событие `grc.assessment.updated`, процент на карточке «Аттестации» на Главной обновился;
   - отправка документа на утверждение → уведомление у пользователей с `approve` в проекте, у автора — нет;
   - пользователь с ролями только в «Сканере» не видит вкладку «Аттестации», `GET /api/grc/summary?project=…` — `403 no_product_roles`.
