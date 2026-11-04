import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import type { ClassificationDetail, Definition, Outcome, Table, TraceStep } from "../lib/classification";
import type { ObjectFull } from "../lib/objects";
import { fakeApi, json } from "../test/fakeApi";

const METH = {
  id: "u2",
  username: "meth",
  display_name: "Иванова А. А.",
  roles: ["methodologist", "approve"],
  permissions: ["view", "objects.edit", "classification.edit", "approve"],
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
  internet: false,
  host_count: 0,
  segment_count: 0,
  updated_at: "2026-11-04T10:00:00Z",
  purpose: null,
  boundaries: null,
  interconnections: [],
  responsible: [],
  created_at: "2026-11-04T10:00:00Z",
  scanner_synced_at: null,
  scanner_engagement_id: null,
  segments: [],
  classification: null,
};

// Урезанная таблица той же формы, что reference/classification/gis-117.yaml.
const DEF: Definition = {
  groups: [
    { key: "damage", title: "Степень возможного ущерба" },
    { key: "scale", title: "Масштаб системы" },
  ],
  inputs: [
    {
      key: "damage",
      group: "damage",
      label: "Ущерб",
      options: [
        { value: "high", label: "Высокая" },
        { value: "low", label: "Низкая" },
      ],
    },
    {
      key: "scale",
      group: "scale",
      label: "Масштаб",
      options: [
        { value: "federal", label: "Федеральный" },
        { value: "object", label: "Объектовый" },
      ],
    },
  ],
  steps: [
    {
      key: "significance",
      label: "Уровень значимости",
      method: "first_match",
      values: [
        { value: "УЗ1", label: "УЗ1" },
        { value: "УЗ3", label: "УЗ3" },
      ],
      rows: [
        { id: "uz1", when: { damage: ["high"] }, value: "УЗ1" },
        { id: "uz3", when: {}, value: "УЗ3" },
      ],
    },
    {
      key: "class",
      label: "Класс защищённости",
      method: "first_match",
      rows: [
        { id: "k1", when: { significance: ["УЗ1"] }, value: "К1" },
        { id: "k3-fed", when: { significance: ["УЗ3"], scale: ["federal"] }, value: "К2", source: { clause: "п. 9" } },
        { id: "k3-obj", when: { significance: ["УЗ3"], scale: ["object"] }, value: "К3" },
      ],
    },
  ],
  result: {
    key: "class",
    label: "Класс защищённости",
    values: [
      { value: "К1", label: "К1 — первый класс" },
      { value: "К2", label: "К2 — второй класс" },
      { value: "К3", label: "К3 — третий класс" },
    ],
  },
};

const SOURCE = { document: "Приказ ФСТЭК России №117", note: "Заглушка: сверить с текстом" };

const TABLE: Table = {
  regime: "117",
  regime_title: "ФСТЭК №117 (ГИС)",
  title: "Класс защищённости ГИС",
  version: "117-stub-1",
  revision: 1,
  origin: "stub",
  source: SOURCE,
  verified: false,
  verified_by_name: null,
  verified_at: null,
  updated_at: "2026-11-04T10:00:00Z",
  gaps: 0,
  definition: DEF,
  definition_hash: "h",
  revisions: [],
};

const TRACE: TraceStep[] = [
  {
    key: "significance",
    label: "Уровень значимости",
    method: "first_match",
    value: "УЗ3",
    row_id: "uz3",
    matched: {},
    source: SOURCE,
    note: null,
  },
  {
    key: "class",
    label: "Класс защищённости",
    method: "first_match",
    value: "К2",
    row_id: "k3-fed",
    matched: { significance: "УЗ3", scale: "federal" },
    source: { ...SOURCE, clause: "п. 9" },
    note: null,
  },
];

const OUTCOME: Outcome = {
  regime: "117",
  result: "К2",
  result_label: "К2 — второй класс",
  values: { significance: "УЗ3", class: "К2" },
  trace: TRACE,
  table_version: "117-stub-1",
  table_revision: 1,
  table_verified: false,
  table_source: SOURCE,
};

const DETAIL: ClassificationDetail = {
  id: "c1",
  object_id: "o1",
  regime: "117",
  inputs: { damage: "low", scale: "federal" },
  result: "К2",
  result_label: "К2 — второй класс",
  values: OUTCOME.values,
  trace: TRACE,
  justification: "Письмо заказчика",
  table_version: "117-stub-1",
  table_revision: 1,
  table_verified: false,
  status: "draft",
  created_at: "2026-11-04T11:00:00Z",
  created_by: "u3",
  created_by_name: "Петров П. П.",
  approved_at: null,
  approved_by_name: null,
  approval_comment: null,
  unverified_acknowledged: false,
  superseded_at: null,
  table_changed: false,
  table_snapshot: DEF,
  table_source: SOURCE,
  reproducible: true,
};

function renderAt(path: string) {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

it("мастер: шаги по группам, результат со сработавшими строками, сохранение черновика", async () => {
  const mine = { ...DETAIL, created_by: "u2", created_by_name: "Иванова А. А." };
  const calls = fakeApi({
    "GET /me": () => json(METH),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json(OBJ),
    "GET /objects/o1/hosts": () => json([]),
    "GET /refs/classification-tables/117": () => json(TABLE),
    "GET /objects/o1/classifications": () => json([]),
    "POST /objects/o1/classifications/preview": () => json(OUTCOME),
    "POST /objects/o1/classifications": () => json(mine, 201),
    "GET /classifications/c1": () => json(mine),
  });
  renderAt("/objects/o1?tab=classification");

  fireEvent.click(await screen.findByRole("button", { name: /Определить/ }));
  const wizard = screen.getByRole("region", { name: "Мастер классификации" });
  const next = within(wizard).getByRole("button", { name: /Далее/ });
  expect(next).toBeDisabled();
  fireEvent.click(within(wizard).getByLabelText("Низкая"));
  fireEvent.click(next);
  fireEvent.click(within(wizard).getByLabelText("Федеральный"));
  fireEvent.click(within(wizard).getByRole("button", { name: /Далее/ }));

  expect(await within(wizard).findByText("Таблица требует сверки — результат предварительный")).toBeInTheDocument();
  expect(calls.find((c) => c.path.endsWith("/preview"))?.body).toEqual({
    inputs: { damage: "low", scale: "federal" },
  });
  // Сработавшая строка выделена и несёт пункт документа.
  const hit = within(wizard).getAllByRole("row").find((r) => r.getAttribute("aria-current") === "true" && /К2/.test(r.textContent ?? ""))!;
  expect(hit).toHaveTextContent("п. 9");

  fireEvent.change(within(wizard).getByPlaceholderText(/письма заказчика/), { target: { value: "Письмо" } });
  fireEvent.click(within(wizard).getByRole("button", { name: /Сохранить черновик/ }));
  await waitFor(() =>
    expect(calls.find((c) => c.method === "POST" && c.path === "/objects/o1/classifications")?.body).toEqual({
      inputs: { damage: "low", scale: "federal" },
      justification: "Письмо",
    }),
  );
  // Свой расчёт открывается в шторке, утвердить его нельзя.
  const drawer = await screen.findByRole("dialog");
  expect(await within(drawer).findByText("Нельзя утвердить собственный расчёт")).toBeInTheDocument();
  expect(within(drawer).getByRole("button", { name: /Утвердить/ })).toBeDisabled();
});

it("утверждение чужого расчёта по несверенной таблице требует подтверждения", async () => {
  const approved = { ...DETAIL, status: "approved" as const, approved_by_name: "Иванова А. А.", approved_at: "2026-11-04T12:00:00Z", unverified_acknowledged: true };
  const calls = fakeApi({
    "GET /me": () => json(METH),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json({ ...OBJ, classification: { id: "c1", result: "К2", short: "К2", result_label: "К2 — второй класс", status: "draft" } }),
    "GET /objects/o1/hosts": () => json([]),
    "GET /refs/classification-tables/117": () => json(TABLE),
    "GET /objects/o1/classifications": () => json([DETAIL]),
    "GET /classifications/c1": () => json(DETAIL),
    "POST /classifications/c1/approve": () => json(approved),
  });
  renderAt("/objects/o1?tab=classification");

  fireEvent.click(await screen.findByRole("button", { name: /Черновик/ }));
  const drawer = await screen.findByRole("dialog");
  expect(await within(drawer).findByText("Письмо заказчика")).toBeInTheDocument();
  expect(within(drawer).getByText("Пересчёт по снимку таблицы совпадает")).toBeInTheDocument();
  fireEvent.click(within(drawer).getByRole("button", { name: /Утвердить/ }));

  const modal = await screen.findByRole("dialog", { name: "Утвердить классификацию" });
  const submit = within(modal).getByRole("button", { name: "Утвердить" });
  expect(submit).toBeDisabled();
  fireEvent.click(within(modal).getByLabelText(/Утверждаю по несверенной таблице/));
  fireEvent.click(submit);
  await waitFor(() =>
    expect(calls.find((c) => c.path === "/classifications/c1/approve")?.body).toEqual({
      comment: null,
      acknowledge_unverified: true,
    }),
  );
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Утвердить классификацию" })).not.toBeInTheDocument());
});

it("наблюдатель видит классификацию без кнопок расчёта", async () => {
  fakeApi({
    "GET /me": () => json({ ...METH, roles: ["viewer"], permissions: ["view"] }),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json(OBJ),
    "GET /objects/o1/hosts": () => json([]),
    "GET /refs/classification-tables/117": () => json(TABLE),
    "GET /objects/o1/classifications": () => json([]),
  });
  renderAt("/objects/o1?tab=classification");
  expect(await screen.findByText("Расчёта ещё не было.")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Определить/ })).not.toBeInTheDocument();
});
