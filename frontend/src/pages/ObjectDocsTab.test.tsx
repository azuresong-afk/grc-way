import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import type { ObjectFull } from "../lib/objects";
import { dispositionName, type DocBrief, type DocField, type DocTypeDetail, type DocumentsList } from "../lib/objectDocs";
import { fakeApi, json } from "../test/fakeApi";

const METH = {
  id: "u2",
  username: "meth",
  display_name: "Иванова А. А.",
  roles: ["methodologist"],
  permissions: ["view", "objects.edit", "documents.edit", "projects.manage"],
};

const PROJECT = {
  id: "p1",
  customer_id: "c1",
  client: "ГБУ «Центр»",
  name: "Аттестация ГИС",
  contract_ref: null,
  period_from: null,
  period_to: null,
  status: "active",
  scanner_engagement_id: null,
  platform_project_id: null,
  created_at: "2026-11-01T10:00:00Z",
  members: [],
};

const OBJ: ObjectFull = {
  id: "o1",
  project_id: "p1",
  kind: "gis",
  name: "ГИС «Учёт»",
  regime: "117",
  status: "active",
  internet: true,
  host_count: 2,
  segment_count: 0,
  updated_at: "2026-11-04T10:00:00Z",
  purpose: "Учёт",
  boundaries: null,
  interconnections: [],
  responsible: [],
  created_at: "2026-11-04T10:00:00Z",
  scanner_synced_at: null,
  scanner_engagement_id: null,
  segments: [],
};

const field = (f: Partial<DocField> & Pick<DocField, "key" | "title" | "state">): DocField => ({
  source: "Объект → Описание",
  tab: "description",
  required: false,
  value: null,
  total: null,
  missing: null,
  missing_examples: null,
  ...f,
});

const FIELDS: DocField[] = [
  field({ key: "object.name", title: "Наименование объекта", state: "filled", value: "ГИС «Учёт»", required: true }),
  field({ key: "object.boundaries", title: "Границы объекта", state: "empty", required: true }),
  field({
    key: "hosts[].os",
    title: "Операционная система",
    state: "partial",
    tab: "composition",
    total: 2,
    missing: 1,
    missing_examples: ["10.0.0.2"],
    required: true,
  }),
];

const V1: DocBrief = {
  id: "d1",
  doc_type: "tech-passport",
  title: "Технический паспорт объекта",
  version: 1,
  status: "draft",
  status_title: "Проект",
  watermark: true,
  watermark_reasons: ["Документ не утверждён"],
  counts: { total: 3, empty: 2, required_empty: 2 },
  docx_size: 40960,
  pdf_size: null,
  pdf_error: "PDF не сформирован: LibreOffice (soffice) не установлен или выключен",
  created_at: "2026-11-05T10:00:00Z",
  created_by_name: "Иванова А. А.",
};

const TYPE: DocTypeDetail = {
  code: "tech-passport",
  title: "Технический паспорт объекта",
  description: "Состав объекта, хосты и СЗИ.",
  template: "tech-passport.docx",
  template_found: true,
  counts: { total: 3, empty: 2, required_empty: 2 },
  watermark_reasons: ["Документ не утверждён"],
  changed: true,
  latest: V1,
  versions: [V1],
  fields: FIELDS,
  unverified: [{ title: "Таблица классификации (Приказ ФСТЭК России №117)", note: "версия 117-stub-1" }],
};

const LIST: DocumentsList = { types: [TYPE], pdf_available: false, can_edit: true, sees_drafts: true };

function renderAt(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

it("вкладка «Документы»: карта полей, несверенные записи, формирование новой версии", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  const calls = fakeApi({
    "GET /me": () => json(METH),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json(OBJ),
    "GET /objects/o1/hosts": () => json([]),
    "GET /objects/o1/documents": () => json(LIST),
    "GET /objects/o1/documents/types/tech-passport": () => json(TYPE),
    "POST /objects/o1/documents": () => json({ ...V1, id: "d2", version: 2, fields: FIELDS, created: true }, 201),
  });
  renderAt("/objects/o1?tab=documents");

  expect(await screen.findByRole("heading", { name: /Технический паспорт объекта/ })).toBeInTheDocument();
  expect(screen.getByText(/не сверенные методистом: Таблица классификации/)).toBeInTheDocument();
  expect(screen.getByText(/на сервере нет LibreOffice/)).toBeInTheDocument();
  expect(screen.getByText("Данные изменились")).toBeInTheDocument();

  const gap = screen.getByText("Границы объекта").closest("tr")!;
  expect(within(gap).getByText("Пусто")).toHaveClass("pill-danger");
  expect(within(gap).getByRole("link", { name: /Заполнить: Описание/ })).toHaveAttribute("href", "/objects/o1");
  const os = screen.getByText("Операционная система").closest("tr")!;
  expect(within(os).getByText("нет у 1 из 2")).toBeInTheDocument();
  expect(within(os).getByRole("link", { name: /Заполнить: Состав/ })).toHaveAttribute(
    "href",
    "/objects/o1?tab=composition",
  );

  // Фильтр «Нужно заполнить» прячет заполненные поля.
  fireEvent.click(screen.getByRole("button", { name: /Нужно заполнить · 2/ }));
  expect(screen.queryByText("Наименование объекта")).not.toBeInTheDocument();

  // PDF у версии нет — кнопка неактивна, причина в подсказке.
  const ver = screen.getByText("v1").closest("tr")!;
  expect(within(ver).getByRole("button", { name: /PDF/ })).toBeDisabled();
  expect(within(ver).getByRole("button", { name: /PDF/ })).toHaveAttribute("title", V1.pdf_error);

  fireEvent.click(screen.getByRole("button", { name: /Сформировать версию 2/ }));
  expect(await screen.findByText("Сформирована версия 2 (только DOCX)")).toBeInTheDocument();
  await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
  expect(calls.find((c) => c.method === "POST")?.body).toEqual({ type: "tech-passport" });
});

it("наблюдатель видит пояснение вместо проектов и не формирует документ", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  fakeApi({
    "GET /me": () => json({ ...METH, roles: ["viewer"], permissions: ["view"] }),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json(OBJ),
    "GET /objects/o1/hosts": () => json([]),
    "GET /objects/o1/documents": () =>
      json({ ...LIST, can_edit: false, sees_drafts: false, types: [{ ...TYPE, versions: [], latest: null }] }),
    "GET /objects/o1/documents/types/tech-passport": () => json({ ...TYPE, versions: [], latest: null }),
  });
  renderAt("/objects/o1?tab=documents");
  expect(await screen.findByText(/Здесь появятся утверждённые документы/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Сформировать/ })).not.toBeInTheDocument();
  expect(screen.getByText("Документ ещё не формировался.")).toBeInTheDocument();
});

it("имя файла из Content-Disposition", () => {
  expect(
    dispositionName(
      "attachment; filename=\"a.docx\"; filename*=UTF-8''%D0%9F%D0%B0%D1%81%D0%BF%D0%BE%D1%80%D1%82.docx",
      "x",
    ),
  ).toBe("Паспорт.docx");
  expect(dispositionName('attachment; filename="a.pdf"', "x")).toBe("a.pdf");
  expect(dispositionName(null, "x")).toBe("x");
});
