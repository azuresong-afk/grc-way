import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import type { ObjectFull } from "../lib/objects";
import {
  dispositionName,
  type DocBrief,
  type DocField,
  type DocFull,
  type DocTypeDetail,
  type DocumentsList,
} from "../lib/objectDocs";
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
  template_name: "tech-passport.docx",
  template_custom: false,
  font: "astra",
  font_title: "PT Astra Serif",
  submitted_at: null,
  submitted_by_name: null,
  approved_at: null,
  approved_by_name: null,
  approval_comment: null,
  unverified_acknowledged: false,
  superseded_at: null,
};

const TYPE: DocTypeDetail = {
  code: "tech-passport",
  title: "Технический паспорт объекта",
  description: "Состав объекта, хосты и СЗИ.",
  template: "tech-passport.docx",
  template_found: true,
  template_ref: {
    custom: false,
    name: "tech-passport.docx",
    id: null,
    uploaded_at: null,
    uploaded_by_name: null,
    comment: null,
  },
  font: "astra",
  counts: { total: 3, empty: 2, required_empty: 2 },
  watermark_reasons: ["Документ не утверждён"],
  changed: true,
  latest: V1,
  approved: null,
  versions: [V1],
  fields: FIELDS,
  unverified: [{ title: "Таблица классификации (Приказ ФСТЭК России №117)", note: "версия 117-stub-1" }],
};

const PLAN: DocTypeDetail = {
  ...TYPE,
  code: "remediation-plan",
  title: "План мероприятий по устранению несоответствий",
  template: "remediation-plan.docx",
  changed: false,
  latest: { ...V1, id: "p1v1", doc_type: "remediation-plan", title: "План" },
  versions: [],
};

const FONTS = [
  { code: "astra" as const, title: "PT Astra Serif" },
  { code: "inter" as const, title: "Inter" },
];

const LIST: DocumentsList = {
  types: [TYPE, PLAN],
  pdf_available: false,
  can_edit: true,
  can_approve: false,
  sees_drafts: true,
  font: "astra",
  fonts: FONTS,
};

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
  // Комплект: оба документа в таблице, у паспорта данные изменились.
  expect(screen.getByRole("button", { name: "План мероприятий по устранению несоответствий" })).toBeInTheDocument();
  expect(screen.getAllByText("Данные изменились").length).toBeGreaterThan(0);
  expect(screen.getByRole("radio", { name: "PT Astra Serif" })).toHaveAttribute("aria-checked", "true");

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
  const ver = screen
    .getAllByText("v1")
    .map((el) => el.closest("tr")!)
    .find((tr) => within(tr).queryByRole("button", { name: /PDF/ }))!;
  expect(within(ver).getByRole("button", { name: /PDF/ })).toBeDisabled();
  expect(within(ver).getByRole("button", { name: /PDF/ })).toHaveAttribute("title", V1.pdf_error);

  fireEvent.click(screen.getByRole("button", { name: /Сформировать версию 2/ }));
  expect(await screen.findByText("Сформирована версия 2 (только DOCX)")).toBeInTheDocument();
  await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
  expect(calls.find((c) => c.method === "POST")?.body).toEqual({ type: "tech-passport" });
});

it("шрифт комплекта, выбор документа и свой шаблон", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  let font = "astra";
  const calls = fakeApi({
    "GET /me": () => json(METH),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json(OBJ),
    "GET /objects/o1/hosts": () => json([]),
    "GET /objects/o1/documents": () => json({ ...LIST, font }),
    "GET /objects/o1/documents/types/tech-passport": () => json(TYPE),
    "GET /objects/o1/documents/types/remediation-plan": () => json(PLAN),
    "PUT /objects/o1/documents/settings": (init) => {
      font = (JSON.parse(String(init?.body)) as { font: string }).font;
      return json({ font });
    },
    "POST /document-templates/remediation-plan": () =>
      json({ id: "t1", doc_type: "remediation-plan", name: "Бланк.docx", active: true }, 201),
  });
  renderAt("/objects/o1?tab=documents");
  await screen.findByRole("heading", { name: /Технический паспорт объекта/ });

  fireEvent.click(screen.getByRole("radio", { name: "Inter" }));
  await waitFor(() => expect(screen.getByRole("radio", { name: "Inter" })).toHaveAttribute("aria-checked", "true"));
  expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ font: "inter" });

  fireEvent.click(screen.getByRole("button", { name: "План мероприятий по устранению несоответствий" }));
  expect(await screen.findByRole("heading", { name: /План мероприятий/ })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "загрузить свой" }));
  const dialog = await screen.findByRole("dialog");
  const input = dialog.querySelector('input[type="file"]') as HTMLInputElement;
  fireEvent.change(input, { target: { files: [new File(["PK"], "Бланк.docx")] } });
  fireEvent.click(within(dialog).getByRole("button", { name: /Загрузить/ }));
  await waitFor(() => expect(calls.some((c) => c.path === "/document-templates/remediation-plan")).toBe(true));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
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
  expect(await screen.findByText(/Здесь — утверждённые документы/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Сформировать/ })).not.toBeInTheDocument();
  expect(screen.getByText("Документ ещё не формировался.")).toBeInTheDocument();
});

const BOSS = {
  id: "u3",
  username: "boss",
  display_name: "Смирнов С. С.",
  roles: ["viewer", "approve"],
  permissions: ["view", "approve"],
};

const V2: DocBrief = {
  ...V1,
  id: "d2",
  version: 2,
  status: "review",
  status_title: "На согласовании",
  submitted_at: "2026-11-05T11:00:00Z",
  submitted_by_name: "Иванова А. А.",
};

const V2_FULL: DocFull = {
  ...V2,
  context_hash: "h",
  fields: FIELDS,
  unverified: [{ title: "Таблица классификации (Приказ ФСТЭК России №117)", note: "" }],
  reviews: [
    {
      action: "submit",
      from_status: "draft",
      to_status: "review",
      comment: "Прошу согласовать",
      actor_name: "Иванова А. А.",
      at: "2026-11-05T11:00:00Z",
    },
  ],
  actions: {
    submit: false,
    send_back: true,
    approve: true,
    approve_blocker: null,
  },
  siblings: [V2, V1],
};

it("утверждающий утверждает версию с отметкой о несверенных записях и сравнивает версии", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  const withV2 = { ...TYPE, latest: V2, versions: [V2, V1] };
  const calls = fakeApi({
    "GET /me": () => json(BOSS),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json(OBJ),
    "GET /objects/o1/hosts": () => json([]),
    "GET /objects/o1/documents": () => json({ ...LIST, can_edit: false, can_approve: true, types: [withV2] }),
    "GET /objects/o1/documents/types/tech-passport": () => json(withV2),
    "GET /documents/d2": () => json(V2_FULL),
    "POST /documents/d2/approve": () =>
      json({
        ...V2_FULL,
        status: "approved",
        status_title: "Утверждён",
        approved_at: "2026-11-05T12:00:00Z",
        approved_by_name: "Смирнов С. С.",
        unverified_acknowledged: true,
        actions: {
          submit: false,
          send_back: false,
          approve: false,
          approve_blocker: null,
        },
      }),
    "GET /documents/d2/compare": () =>
      json({
        old: V1,
        new: V2,
        meta: [{ title: "Статус", before: "Проект", after: "На согласовании" }],
        fields: [
          {
            key: "object.boundaries",
            title: "Границы объекта",
            tab: "description",
            before: null,
            after: "Здание 1",
            state_before: "empty",
            state_after: "filled",
          },
        ],
        hunks: [
          {
            old_start: 4,
            new_start: 4,
            lines: [
              { op: "same", text: "1. Общие сведения" },
              { op: "del", text: "Границы | [не заполнено: Границы объекта]" },
              { op: "add", text: "Границы | Здание 1" },
            ],
          },
        ],
        added: 1,
        removed: 1,
        truncated: false,
        text_error: null,
      }),
  });
  renderAt("/objects/o1?tab=documents");
  await screen.findByRole("heading", { name: /Технический паспорт объекта/ });
  expect(screen.getAllByText("На согласовании").length).toBeGreaterThan(0);

  fireEvent.click(document.querySelector(".doc-versions tbody tr")!);
  const drawer = await screen.findByRole("dialog");
  expect(await within(drawer).findByText("Прошу согласовать")).toBeInTheDocument();
  fireEvent.click(within(drawer).getByRole("button", { name: /Утвердить/ }));
  const modal = (await screen.findAllByRole("dialog")).at(-1)!;
  const ok = within(modal).getByRole("button", { name: "Утвердить" });
  expect(ok).toBeDisabled(); // несверенные записи — нужна отметка
  fireEvent.click(within(modal).getByRole("checkbox"));
  fireEvent.click(ok);
  await waitFor(() => expect(calls.some((c) => c.path === "/documents/d2/approve")).toBe(true));
  expect(calls.find((c) => c.path === "/documents/d2/approve")?.body).toEqual({
    comment: null,
    acknowledge_unverified: true,
  });
  expect(await within(drawer).findByText(/утверждён с несверенными записями/)).toBeInTheDocument();

  fireEvent.click(within(drawer).getByRole("button", { name: /Сравнить/ }));
  expect(await screen.findByText("Сравнение версий")).toBeInTheDocument();
  expect(await screen.findByText("Здание 1")).toBeInTheDocument();
  expect(screen.getByText("Границы | Здание 1").closest(".text-diff-line")).toHaveClass("add");
  expect(screen.queryByText("1. Общие сведения")).not.toBeInTheDocument(); // только изменения
  expect(calls.some((c) => c.path.startsWith("/documents/d2/compare"))).toBe(true);
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
