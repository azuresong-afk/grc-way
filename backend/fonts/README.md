# Шрифты документов комплекта

Документы комплекта (встроенные шаблоны) оформляются шрифтом, выбранным для объекта
на вкладке «Документы»: **PT Astra Serif** (по умолчанию) или **Inter**.

- **Inter** ставится в образ `app` пакетом `fonts-inter`.
- **PT Astra Serif** в репозиторий не входит: положите файлы шрифта
  (`PTAstraSerif-Regular.ttf`, `PTAstraSerif-Bold.ttf`, `PTAstraSerif-Italic.ttf`,
  `PTAstraSerif-BoldItalic.ttf`; распространяется по SIL Open Font License) в этот
  каталог и пересоберите образ (`make up`). Без них PDF собирается с Liberation Serif —
  шрифт метрически совместим, поэтому строки и страницы разбиваются так же. В DOCX
  остаётся имя «PT Astra Serif», и на компьютере со шрифтом (Astra Linux или
  установленный шрифт) документ открывается им.

`60-grc-fonts.conf` — правила fontconfig для LibreOffice: замена PT Astra Serif на
Liberation Serif и Inter на Liberation Sans, если нужного шрифта нет.
