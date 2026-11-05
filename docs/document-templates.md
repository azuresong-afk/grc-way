# Свой шаблон документа комплекта

Каждый документ комплекта (вкладка объекта «Документы») формируется из DOCX-шаблона.
Встроенные шаблоны лежат в `templates/docx/` и собираются скриптом
`backend/tools/build_doc_templates.py`. Методист может заменить шаблон любого документа
своим: «Документы» → документ → «Шаблон» → «загрузить свой». Скачайте встроенный шаблон
(«скачать встроенный»), поправьте его в Word / LibreOffice и загрузите обратно.

Свой шаблон действует **для всех проектов и объектов** (по коду документа). Прежние
загрузки остаются в истории; «вернуть встроенный» снимает свой шаблон. Уже
сформированные версии не меняются, а для следующей версии объект покажет «Данные
изменились», потому что поменялся шаблон.

## Синтаксис

Шаблон заполняется через [docxtpl](https://docxtpl.readthedocs.io/) (Jinja2):

| Что | Как писать |
| --- | --- |
| Значение | `{{ object.name }}` |
| Условие в абзаце | `{% if classification.result %}…{% else %}…{% endif %}` |
| Абзацы целиком в цикле или условии | `{%p for s in org.sections %}` … `{%p endfor %}` (каждый тег в отдельном абзаце) |
| Строки таблицы в цикле | `{%tr for h in hosts %}` в строке перед строкой данных, `{%tr endfor %}` в строке после |
| Пустой список | `{% if hosts %}`… таблица …`{% else %}{{ empty.hosts }}{% endif %}` |

Если обязательное поле карты документа пусто, на его месте выводится
«[не заполнено: …]». Пустое поле у элемента списка выводится как «[не указано]». Для пустого
списка заглушка лежит в `empty.<путь>`, например `empty.object.responsible`.

Шрифт объекта (PT Astra Serif / Inter) подставляется в стили только встроенных шаблонов.
Свой шаблон печатается своими шрифтами.

## Ограничения при загрузке

- Только DOCX: не больше 10 МБ, не больше 64 МБ в распакованном виде, без шифрования.
- Макросы (`vbaProject.bin`) не принимаются.
- В шаблоне можно использовать только разделы из списка ниже и `doc`, `empty`. Шаблон с
  неизвестным именем отклоняется, и сообщение называет это имя.
- Шаблон выполняется в песочнице Jinja: обращения к служебным атрибутам Python
  (`__class__` и т. п.) запрещены. Ошибка в шаблоне видна при формировании документа.

Документ хранит и хэширует только те разделы, которые использует его шаблон. Поэтому
шаблон без `threat_model` не станет «изменённым» после правки модели угроз.

## Разделы контекста

Даты — строки `ДД.ММ.ГГГГ`, проценты и V — строки с запятой (`43,5 %`, `11,00`).
Пустое значение — `None` или пустой список. «`[]`» — список, у элементов перечислены поля.

### `doc` — сам документ
`title` (заголовок по режиму объекта), `version`, `generated` (дата формирования),
`status_title` («Проект», «Утверждён»), `approved` (дата утверждения) и `approved_by`
(кто утвердил) — у проекта пустые, заполняются, когда утверждение пересобирает документ
(задача 3.3). Пример: `{{ doc.status_title }}{% if doc.approved %} {{ doc.approved }},
{{ doc.approved_by }}{% endif %}`.

### `customer`, `project`
- `customer`: `name`, `inn`, `ogrn`, `address`.
- `project`: `name`, `contract_ref`, `period_from`, `period_to`.

### `object`
`name`, `kind` (`gis` / `ispdn` / `kii` / `other`), `kind_title`, `regime` (`117` / `21` /
`239`), `regime_title`, `purpose`, `boundaries`, `internet_title` (есть / нет).
- `responsible[]`: `name`, `position`, `role`, `phone`, `email`.
- `interconnections[]`: `system`, `owner`, `direction_title`, `channel`, `description`.

### `classification` — утверждённый расчёт
`result`, `result_label`, `regime_title`, `approved`, `approved_by`, `justification`,
`table_version`.
- `steps[]`: `label`, `value`, `matched`, `source`.
- `inputs[]`: `name`, `value`.

### `segments[]`, `hosts[]`, `szi[]`
- `segments[]`: `name`, `description`, `host_count`.
- `hosts[]`: `address`, `hostname`, `role`, `os`, `segment`, `source_title`,
  `internet_title`.
- `szi[]`: `name`, `kind_title`, `vendor`, `version`, `cert_number`, `valid_to`,
  `trust_level`, `state_title`, `placement`, `measures`.

### `snapshot` — последний снимок «Сканера»
`number`, `run_id`, `run_name`, `run_finished`, `imported`, `imported_by`, `modules`,
`level`, `percent`, `passed`, `failed`, `hosts`, `coverage_gaps`.

### `measures` — набор мер и оценка
`profile`, `profile_short`, `level`.
- `adaptation`: `version`, `status_title`, `approved`, `approved_by`.
- `stats`: `percent`, `auto_percent`, `manual_percent`, `total`, `implemented`, `partial`,
  `not_implemented`, `unassessed`, `excluded`, `not_applicable`, `compensated`,
  `confirmed`, `partial_weight`.
- `groups[]`: `code`, `title`, `implemented`, `nonconforming`, `unassessed`, `rows[]`.
- `excluded[]`, `compensated[]`, `added[]` и `groups[].rows[]` — меры с полями: `id`, `title`,
  `group`, `method_title`, `status_title`, `adaptation_title`, `reason`, `compensating`,
  `auto`, `failed_hosts`, `recommendation`, `manual`, `comment`, `confirmed`.

Список мер называется `rows`, а не `items`: в Jinja `x.items` — метод словаря.

### `threat_model` — утверждённая версия модели угроз, без неё последний черновик
`version`, `status`, `status_title`, `approved`, `approved_by`, `intruders_relevant`.
- `consequences[]`: `code`, `title`, `justification`.
- `objects[]`: `name`, `description`, `hosts`, `impacts`, `consequences`.
- `intruders[]`: `code`, `title`, `relevant`, `relevant_title`, `capability`,
  `justification`.
- `methods[]`: `code`, `title`, `interfaces`, `objects`, `intruders`.
- `scenarios[]`: `tactic`, `title`, `techniques`, `note`.
- `threats[]` (все угрозы) и `relevant_threats[]` (только актуальные): `code`, `title`,
  `relevant`, `relevant_title`, `justification`, `intruders`, `objects`, `consequences`,
  `methods`, `tactics`, `findings`.
- `counts`: `total`, `relevant`, `not_relevant`, `undecided`.
- `notes`: `consequences`, `objects`, `intruders`, `methods`, `scenarios`.

### `vulns` — реестр уязвимостей с оценкой по Методике 2025
`snapshot` — номер снимка.
- `methodology`: `short`, `title`, `issuer`, `issued`, `number`, `version`, `formula`.
- `levels[]`: `code`, `title`, `condition` (диапазон V), `deadline` (срок устранения).
- `rows[]`: `bdu_id`, `title`, `cve`, `hosts`, `source_title`, `state_title`, `v`, `level`,
  `level_title`, `assessed`, `deadline`, `overdue`, `detected`.
- `counts`: `critical`, `high`, `medium`, `low`, `total`, `assessed`, `not_assessed`,
  `overdue`, `not_detected`.

### `nonconformities[]`, `vuln_plan[]` — строки плана устранения
`kind_title`, `ref`, `title`, `status_title`, `details`, `action`. У строк `vuln_plan` есть
ещё `deadline`.

### `org` — типовой текст ОРД (`reference/documents/org-docs.yaml`)
`version`.
- `sections[]`: `number`, `code`, `title`, `purpose`, `paragraphs[]` (строки),
  `measures[]` (`id`, `title`, `status_title`).

### `normative[]` — нормативные документы режима объекта
`short`, `title`, `issuer`, `issued`, `number`.

### `unverified[]` — несверенные записи справочников
`section`, `title`, `note`. В документ попадают только записи разделов, которые он использует.
Если список не пуст, документ получает водяной знак «Проект».
