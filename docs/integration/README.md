# Интеграция продукта с «Платформой»: общая часть

Документ для команд «Сканера», «Устранения» и «Аттестации». Здесь — то, что одинаково для всех продуктов; что делает конкретный продукт — в отдельном файле:

| Продукт | Файл |
|---|---|
| «Сканер» (`scanner`) | [`scanner.md`](scanner.md) |
| «Устранение» (`vm`) | [`vm.md`](vm.md) |
| «Аттестация» (`grc`) | [`grc.md`](grc.md) |

Источник требований — контракт v1 (`docs/spec/03-platforma.md`, раздел «Контракт платформы v1») и его уточнения [`docs/contract-v1.1.md`](../contract-v1.1.md). Если этот документ и контракт расходятся, прав контракт; номера пунктов ниже («п. 2.1») — пункты контракта v1.1.

**Как перенести в продукт.** Скопируйте в репозиторий продукта `docs/integration/README.md`, файл своего продукта и каталог `vectors/` целиком. Векторы не меняйте руками: их генерирует платформа (`api/tests/integration_vectors.py`), и тест платформы сверяет файлы с генератором байт в байт. При обновлении контракта копируйте каталог заново.

## 1. Режимы работы

Продукт работает и сам по себе, и внутри платформы, без форков кода. Режим выбирается переменной окружения:

| Переменная | Значение | Что делает |
|---|---|---|
| `AUTH_MODE` | `local` (по умолчанию) \| `platform` | `local` — свой вход и свой справочник проектов, как сейчас; `platform` — всё ниже |

Переменные режима `platform` — те, что передаёт комплект (п. 12 контракта); продукт обязан их понимать и описать в своём `.env.example`:

| Переменная | Значение в комплекте | Зачем |
|---|---|---|
| `AUTH_MODE` | `platform` | режим |
| `PLATFORM_PRODUCT_ID` | `scanner` / `vm` / `grc` | свой id: `aud`, `products.<id>`, `X-Platform-Product` |
| `DATABASE_URL` | `postgresql+psycopg://<id>:<пароль>@db:5432/<id>` | своя база в общем кластере (формат SQLAlchemy) |
| `PLATFORM_URL` | `http://platform-api:8000` | API платформы внутри сети, без префикса `/api/platform`: `GET /projects/{id}`, `POST /auth/token` |
| `PLATFORM_JWKS_URL` | `http://platform-api:8000/.well-known/jwks.json` | открытые ключи для проверки токенов |
| `PLATFORM_EVENTS_URL` | `http://platform-api:8000/events` | отправка событий |
| `PLATFORM_EVENTS_SECRET` | значение `<ID>_EVENTS_SECRET` из `.env` комплекта | HMAC событий в обе стороны |

`iss` токенов — всегда `platform`. Префикс `/api/platform` отрезает шлюз только для браузера; продукт внутри сети ходит в platform-api напрямую.

### 1.1. Запуск в составе комплекта (п. 12)

- Продукт поставляется образом API (`<id>-app`, слушает `:8000`, `HEALTHCHECK` по `/health/ready`) и, по желанию, web-образом (nginx-unprivileged `:8080`, SPA собрана с `VITE_BASE=/<id>/`). Подключается строками `<ID>_IMAGE`, `<ID>_WEB_IMAGE`, `<ID>_DB_PASSWORD`, `<ID>_EVENTS_SECRET` в `.env` комплекта, без правки compose-файлов. Свои секреты и лимиты продукт читает из `deploy/env/<id>.env`.
- **База без прав суперпользователя.** Пользователь `<id>` — владелец базы `<id>`, без `SUPERUSER`, `CREATEDB`, `CREATEROLE`, `REPLICATION`, `BYPASSRLS`. Миграции выполняются им при старте `app`; расширения — только доверенные (`pgcrypto`, `uuid-ossp`, `citext` и т. п.), недоверенное — сообщить, его добавит `deploy/db/provision.sh`. Не создавать других ролей и баз.
- Триггер append-only журнала аудита создаётся владельцем базы — это работает без суперпользователя. Не используйте `SECURITY DEFINER`-функции, принадлежащие `postgres`, и `ALTER SYSTEM`: восстановление из копии (`deploy/restore.sh`) идёт от имени `<id>`.
- Проверка: прогнать миграции на чистом PostgreSQL 16 пользователем `CREATE ROLE <id> LOGIN PASSWORD '…'` (без других атрибутов), владельцем базы `<id>`; затем `pg_dump` → восстановление тем же пользователем.

## 2. Проверка токена (п. 2.1–2.3)

Каждый запрос к API продукта, кроме `GET /manifest` и `GET /health/*`, проверяется так, по порядку:

| # | Проверка | При ошибке |
|---|---|---|
| 1 | Заголовок `Authorization: Bearer <JWT>` есть | `401 {"detail":"not_authenticated"}` |
| 2 | В заголовке JWT `alg` = `EdDSA` (ровно; `none`, `HS256` и прочие — отказ) | `401 invalid_token` |
| 3 | `kid` есть и найден в JWKS. Не найден — перечитать JWKS сразу, но не чаще раза в 30 с; кэш JWKS — 10 мин | `401 invalid_token` |
| 4 | Подпись Ed25519 ключом с этим `kid` | `401 invalid_token` |
| 5 | `iss` = `platform`; `exp` и `iat` есть, `exp` не истёк с допуском 60 с; свой id есть в `aud` | `401 invalid_token` |
| 6 | В `products.<свой id>` непустой список ролей | `403 {"detail":"no_product_roles"}` |
| 7 | Для запросов в проект: `projects` содержит `"*"` или uuid проекта | `403 {"detail":"no_project_access"}` |

На 401 отвечайте с `WWW-Authenticate: Bearer`. Важно различать 401 и 403: на 401 фронтенд делает refresh, на 403 — нет (п. 2.4). Пользователь платформы без ролей в продукте получает **403**, потому что `aud` его токена содержит все продукты установки (п. 2.1).

Утверждения токена пользователя:

```json
{"iss":"platform","sub":"6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b","typ":"user",
 "aud":["scanner","vm","grc","platform"],
 "preferred_username":"ivanov","name":"Иванов И. И.","auth_source":"local",
 "products":{"scanner":["operator","cred_audit"],"vm":["engineer"]},
 "projects":["3e2a8c1f-5b7d-4f9e-a1c3-6d8b0e2f4a61"],"platform_admin":false,
 "iat":1793808000,"exp":1793808900,"jti":"…"}
```

- `typ` — `user` или `service`; нет поля — считать `user`. `auth_source`, `platform_admin` — информационные, права на них не строить.
- Роли берите **только** из `products.<свой id>` и вычисляйте права из них на каждый запрос, как сейчас. Роли других продуктов игнорируйте.
- **Теневой пользователь.** При первом запросе с новым `sub` создайте у себя запись пользователя без пароля (`sub`, `preferred_username`, `name`, `typ`); при следующих — обновляйте имя. Роли в записи не храните: источник истины — токен. Журнал аудита продукта ссылается на эту запись.
- **Сервисный токен** (п. 2.2): `typ: "service"`, `sub` вида `svc:<uuid>`, `aud` — ровно один продукт, `projects` обычно `["*"]`. Проверяется тем же кодом; теневая запись помечается «сервис», действия пишутся в аудит как обычно.
- Ключи ротируются: в JWKS одновременно бывает 2–3 ключа (`active`, `next`, недавно выведенный). Выбирайте ключ строго по `kid`.
- При срочной смене платформа может **отозвать** ключ: он сразу исчезает из JWKS, а событие `platform.keys.rotated` приходит с непустым `revoked`. Получив его, сбросьте кэш JWKS немедленно (без ограничения «не чаще раза в 30 с») и не принимайте токены с этими `kid`, даже если старая копия JWKS ещё в памяти. Для этого продукт подписывается на `platform.keys.rotated` (п. 7.3). Без подписки отозванный ключ живёт в кэше продукта до 10 минут.

Эталонная реализация на Python (FastAPI + PyJWT) — `dev/fakeproduct/auth.py` в репозитории платформы; она проходит все векторы (`dev/tests/test_vectors.py`). Суть:

```python
header = jwt.get_unverified_header(token)
if header.get("alg") != "EdDSA":
    raise unauthorized()
jwk = jwks_cache.get(header.get("kid", ""))       # с перечитыванием по неизвестному kid
if jwk is None:
    raise unauthorized()
claims = jwt.decode(
    token, jwt.PyJWK(jwk).key, algorithms=["EdDSA"],
    audience=PRODUCT_ID, issuer="platform", leeway=60,
    options={"require": ["exp", "iat", "sub", "aud", "iss"]},
)
roles = (claims.get("products") or {}).get(PRODUCT_ID) or []
if not roles:
    raise HTTPException(403, detail="no_product_roles")
```

## 3. Проекты (п. 3.1)

- В режиме `platform` проект создаётся только в платформе. Продукт хранит у себя `platform_project_id` (uuid) и не даёт создавать проекты через свой API и интерфейс.
- Проект приходит в запросе как `?project=<uuid>` (или в пути). Неизвестный продукту uuid — создать «тень» проекта по данным `GET {PLATFORM_URL}/projects/{id}` **с токеном пользователя, который сделал запрос** (сервисный токен туда не подходит: его `aud` — только ваш продукт).
- Ответ платформы: `{id, name, client, contract_ref, period_from, period_to, status, created_at, archived_at}`. Кэшируйте до 5 минут или обновляйте по событию `platform.project.updated {project_id, name, status}`.
- Архивный проект (`status: "archived"`) — только чтение: изменяющие запросы отвечают `409 {"detail":"project_archived"}`.

## 4. Манифест (п. 5.1–5.2)

`GET /manifest` — без авторизации, только метаданные. Платформа читает его по внутреннему адресу раз в минуту и при старте. Полный пример — в файле продукта. Правила:

- `roles` — **все** роли, включая права-надбавки; платформа разрешит выдать только роли из этого списка.
- `admin_roles` — административные роли продукта (матрица доступа подсвечивает их совмещение с рабочими).
- `base_path` = `/<id>/`, `api_base` = `/api/<id>/`; `search_url`, `health_url`, `summary_url` — **с** префиксом `/api/<id>`, а `events.webhook` — **без** него (путь внутри API продукта).
- `GET /health/ready` — `200`, когда продукт готов (БД доступна, миграции применены).

## 5. Сводка для Главной (п. 10)

`GET /summary?project=<uuid>` с токеном пользователя. Ответ за ≤ 3 с (оболочка ждёт 5 с):

```json
{"product":"vm","project_id":"<uuid>","generated_at":"2026-11-04T16:54:52Z",
 "link":"/vm/?project=<uuid>","data":{…}}
```

Состав `data` — в файле продукта. Кроме него можно отдавать общий список показателей `data.kpis[]` (п. 10.1: `{label, value, severity?, link?}`, до 6 штук, и необязательный `note`); оболочка рисует его для продуктов без особого оформления карточки. Новому продукту, которого нет в п. 10, — только так. Пустой проект — нули и `null`, не 404. Без доступа к проекту — 403 `no_project_access`. Запрос должен быть лёгким: агрегаты по индексам, без тяжёлых отчётов.

## 6. Поиск (п. 7)

`GET /search?q=<строка>&project=<uuid>&limit=8` с токеном пользователя, ответ за ≤ 2 с (оболочка ждёт 3 с и показывает остальные продукты, не дожидаясь медленного):

```json
{"items":[{"kind":"ticket","title":"№125 Обновить openssh-server",
           "subtitle":"Назначена: Петров П. П. · Высокий",
           "link":"/vm/tickets/125?project=<uuid>","severity":"high"}]}
```

Пустой `q` — `{"items":[]}`. `link` — относительный путь в своём `base_path` с `?project=`. Ищите только в объектах, которые пользователь вправе видеть.

## 7. События (п. 6)

### 7.1. Отправка

1. Событие пишется в таблицу-outbox **в той же транзакции**, что и изменение данных.
2. Фоновая задача отправляет записи outbox:

```http
POST {PLATFORM_EVENTS_URL}
Content-Type: application/json
X-Platform-Product: vm
X-Event-Id: 7c9e6679-7425-40de-944b-e07fc1f90004
X-Signature: sha256=<hex HMAC-SHA256(тело, PLATFORM_EVENTS_SECRET)>

{"id":"7c9e6679-7425-40de-944b-e07fc1f90004","type":"vm.ticket.created","source":"vm",
 "time":"2026-11-04T16:54:52Z","project_id":"<uuid>","subject":"ticket/125","data":{…},
 "notify":{"users":["<sub>"],"title":"Вам назначена заявка №125","link":"/vm/tickets/125?project=<uuid>"}}
```

- **Подпись считается от байтов тела, которые уходят в сеть.** Сериализуйте JSON один раз, подпишите эти байты и отправьте их же (не передавайте объект в HTTP-клиент, который сериализует заново). Векторы `product_to_platform` и `reserialized_body` показывают, чем это кончается.
- `source` = `X-Platform-Product` = id продукта; `type` начинается с `<id>.` (исключение — `audit.recorded`). `id` — uuid, неизменный при повторах.
- Ответы платформы: `202` — принято; `200 {"duplicate":true}` — уже было, тоже успех; `401` — подпись (проверьте секрет); `422` — конверт не по схеме, повторять бессмысленно — пометить `rejected`. Сеть, `5xx` и прочее — повтор через 1, 5, 15, 60 мин, затем `dead` и разбор вручную.
- `notify` — необязательное: кому из пользователей (`sub`) показать уведомление в колокольчике платформы. `link` — только относительный путь того же origin.
- Обязательные поля `data` для каждого типа — п. 6.2 контракта; примеры всех типов — `vectors/events.json`. Дополнительные поля допустимы.

### 7.2. Приём (подписки)

Если продукт подписан (`events.subscribe` в манифесте), платформа доставляет события `POST` на `<внутренний адрес API продукта><events.webhook>`:

- заголовки `X-Platform-Product: platform`, `X-Event-Id`, `X-Signature` — HMAC **секретом этого продукта** (того же `PLATFORM_EVENTS_SECRET`);
- проверьте подпись (`hmac.compare_digest`) **до** разбора JSON; неверная — `401`;
- подпись считается от **полученных байтов тела как есть**. Платформа пересериализует конверт при доставке (компактный JSON; порядок ключей внутри `data` может отличаться от того, что прислал источник), поэтому никогда не проверяйте HMAC от заново закодированной копии разобранного JSON;
- обработчик идемпотентен по `id`: повтор — `200`, без повторной обработки;
- любой `2xx` — успех; иначе платформа повторит через 1, 5, 15, 60 мин.

### 7.3. События платформы

Платформа сама публикует события с `source: "platform"` (п. 6.2) и доставляет их подписчикам так же, как события продуктов. Рекомендуем каждому продукту добавить в `events.subscribe` манифеста:

| Тип | `data` | Что сделать продукту |
|---|---|---|
| `platform.keys.rotated` | `{kid, revoked[]}` | `kid` — ключ, который начал подписывать; непустой `revoked` — сразу сбросить кэш JWKS и отвергать эти `kid` (п. 2) |
| `platform.project.updated` | `{project_id, name, status}` | обновить теневой проект; `archived` — перевести в режим «только чтение» |
| `platform.user.blocked` | `{sub}` | необязательно: завершить свои фоновые операции от имени пользователя. Выданный access-токен живёт до 15 минут (см. вопрос 3 в `docs/roadmap.md`) |

`project_id` в конвертах `platform.keys.rotated` и `platform.user.blocked` — `null`. Примеры — `vectors/events.json`.

## 8. Фронтенд (п. 2.4, 9, 11)

| Что | Как |
|---|---|
| База SPA | переменная сборки `VITE_BASE` (по умолчанию `/`; в платформе `/<id>/`) |
| База API | `VITE_API_BASE` (по умолчанию `/api`; в платформе `/api/<id>`) |
| Строка вкладок | `VITE_PLATFORM=1` — `Layout` из `@platform/ui` рисует вкладки продуктов |
| Токен | `sessionStorage['platform.token']`; заголовок `Authorization: Bearer …` |
| 401 | один общий на вкладку `POST /api/platform/auth/refresh` (`credentials: "same-origin"`), новый токен — в `platform.token`, повтор запроса; refresh вернул 401 — очистить токен и `location = "/login?next=" + encodeURIComponent(путь + query)` |
| 403 `no_product_roles` | экран «Нет доступа к продукту» со ссылкой на `/`, без refresh |
| Выход | `POST /api/platform/auth/logout`, очистить `platform.token`, записать `localStorage['platform.logout'] = Date.now()`, перейти на `/login` |
| Выход в другой вкладке | слушать `storage` по ключу `platform.logout`: очистить свой `platform.token` и перейти на `/login?next=<путь с query>`. Без этого открытые вкладки работают до истечения access-токена (15 мин), хотя refresh уже отозван. В `@platform/ui` это делают `logout()` и `AuthProvider` (`onLogoutElsewhere`) |
| Проект | `localStorage['platform.project']` + `?project=` в адресе; слушать событие `storage` |
| Тема | `localStorage['platform.theme']` (`dark`/`light`), при чтении учитывать старый `scanner.theme`; слушать `storage` |
| Стили | `@platform/ui` (`import "@platform/ui/styles.css"`); пока пакет не подключён — своя копия стилей «Сканера» с `--radius: 4px`, `--radius-sm: 3px` (п. 9.1) |

Своей страницы входа в режиме `platform` у продукта нет. Хуки `useTheme` и `useProject` и `AuthProvider` из `@platform/ui` уже делают синхронизацию через `storage`.

## 9. Тестовые векторы

Каталог [`vectors/`](vectors/):

| Файл | Что внутри |
|---|---|
| `jwks.json` | JWKS с двумя ключами Ed25519 (`20261104-vec00001` — active, `20261104-vec00002` — next) |
| `jwt.json` | 16 подписанных токенов и ожидаемый ответ продукта на каждый: `200` с ролями и `typ`, `401 invalid_token`, `403 no_product_roles` / `no_project_access` |
| `hmac.json` | тела событий, секреты, заголовки и признак `valid` для проверки HMAC в обе стороны |
| `events.json` | по одному корректному конверту на каждый тип события из п. 6.2, включая события платформы; все проходят схему шины событий платформы |
| `signing-keys.TEST-ONLY.json` | seed тестовых ключей — чтобы подписывать свои токены в тестах. **Ключи опубликованы, в установках не использовать** |

Действующие токены живут до 2100 года (`exp` = 4102444800), просроченный — истёк 04.11.2026, поэтому тесты не требуют подмены часов. Проекты в векторах: A = `3e2a8c1f-5b7d-4f9e-a1c3-6d8b0e2f4a61`, B = `9a7c5e3b-1d2f-4b6a-8c0e-4f6a8b0c2d93`.

Каждый случай в `jwt.json`:

```json
{"name":"user_valid","description":"…","token":"eyJ…",
 "checks":[{"product":"scanner","status":200,"roles":["operator","cred_audit"],"typ":"user","project":"<A>"},
           {"product":"scanner","status":403,"detail":"no_project_access","project":"<B>"},
           {"product":"grc","status":403,"detail":"no_product_roles"}]}
```

Для своего продукта берите проверки, где `product` — ваш id; `project`, если есть, — проект запроса. Пример теста (pytest, FastAPI):

```python
import json, pathlib, pytest

VEC = pathlib.Path(__file__).parents[1] / "docs/integration/vectors"
CASES = json.loads((VEC / "jwt.json").read_text(encoding="utf-8"))["cases"]
PRODUCT = "vm"

@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_platform_jwt(client_with_jwks, case):
    # client_with_jwks — приложение в AUTH_MODE=platform, JWKS подменён содержимым vectors/jwks.json
    for check in (c for c in case["checks"] if c["product"] == PRODUCT):
        project = check.get("project", "3e2a8c1f-5b7d-4f9e-a1c3-6d8b0e2f4a61")
        r = client_with_jwks.get(f"/summary?project={project}",
                                 headers={"Authorization": f"Bearer {case['token']}"})
        assert r.status_code == check["status"], case["name"]
        if "detail" in check:
            assert r.json()["detail"] == check["detail"]
```

В каждом случае есть проверка для каждого из трёх продуктов. Например, `service_vm_to_scanner` в «Сканере» даёт `200`, а в «Устранении» и «Аттестации» — `401` (их id нет в `aud`). Проверка без `project` — запрос вне проекта (или в проекте A: доступ к нему у таких токенов есть).

Для HMAC: `hmac_sha256(case.secret, case.body в UTF-8)` с префиксом `sha256=` совпадает с `headers["X-Signature"]` тогда и только тогда, когда `valid: true`.

## 10. Готовность к включению в платформу

- [ ] `AUTH_MODE=local` работает как раньше (регресс-тесты зелёные).
- [ ] Продукт понимает переменные комплекта (п. 1); миграции и восстановление из копии проходят пользователем БД без прав суперпользователя (п. 1.1).
- [ ] Все векторы `jwt.json` и `hmac.json` проходят в тестах продукта.
- [ ] Теневые пользователи и теневые проекты создаются при первом обращении; создание проектов в режиме `platform` запрещено.
- [ ] `GET /manifest`, `/health/ready`, `/summary`, `/search` отвечают по контракту.
- [ ] Outbox: событие пишется в одной транзакции с изменением, доставка переживает рестарт, повторы 1/5/15/60.
- [ ] Каждая запись своего журнала аудита уходит событием `audit.recorded`.
- [ ] Подписка на `platform.keys.rotated` и `platform.project.updated`; непустой `revoked` сбрасывает кэш JWKS.
- [ ] Фронтенд собран с `VITE_BASE=/<id>/`, `VITE_API_BASE=/api/<id>`, `VITE_PLATFORM=1`; 401/403/выход по п. 2.4, включая «выход отовсюду» по сигналу `platform.logout`.
- [ ] На стенде платформы (`docker compose up` с upstream вашего продукта вместо заглушки): вход в оболочке открывает продукт без повторного входа; выход в любой вкладке сразу уводит на вход все вкладки продукта; пользователь без ролей не видит вкладку и получает 403 от API; карточка на Главной заполнена.
