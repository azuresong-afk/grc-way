import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import type { MeasureSet, ObjectMeasure, StatsBucket } from "../lib/measures";
import type { ObjectFull } from "../lib/objects";
import { fakeApi, json } from "../test/fakeApi";

const METH = {
  id: "u2",
  username: "meth",
  display_name: "Иванова А. А.",
  roles: ["methodologist"],
  permissions: ["view", "objects.edit", "classification.edit", "adaptation.edit"],
};
const BOSS = { ...METH, id: "u9", display_name: "Смирнов С. С.", roles: ["viewer", "approve"], permissions: ["view", "approve"] };

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
  classification: { id: "c1", result: "К2", short: "К2", result_label: "К2 — второй класс", status: "approved" },
};

const CLASS = { id: "c1", result: "К2", result_label: "К2 — второй класс", status: "approved" };

function bucket(over: Partial<StatsBucket> = {}): StatsBucket {
  return {
    total: 2,
    implemented: 1,
    partial: 0,
    not_implemented: 0,
    unassessed: 1,
    excluded: 1,
    not_applicable: 0,
    compensated: 0,
    score: 1,
    percent: 50,
    ...over,
  };
}

function measure(over: Partial<ObjectMeasure>): ObjectMeasure {
  return {
    id: "m1",
    profile_id: "fstec-117",
    measure_id: "КК",
    group_code: "МРП",
    title: "Контроль конфигураций",
    origin: "baseline",
    adaptation: "none",
    adaptation_reason: null,
    compensating_ids: [],
    compensates: [],
    status: "implemented",
    effective_status: "implemented",
    method: "auto",
    checks: ["smb1_disabled"],
    levels: ["К1", "К2", "К3"],
    in_reference: true,
    verified: false,
    owner_id: null,
    owner_name: null,
    comment: null,
    adapted_at: null,
    adapted_by_name: null,
    status_at: null,
    status_by_name: null,
    updated_at: "2026-11-04T10:00:00Z",
    ...over,
  };
}

const MEASURES = [
  measure({}),
  measure({ id: "m2", measure_id: "ВУ", title: "Выявление угроз", method: "manual", checks: [], status: "unassessed", effective_status: "unassessed" }),
  measure({
    id: "m3",
    measure_id: "БД",
    title: "Беспроводной доступ",
    method: "manual",
    checks: [],
    status: "unassessed",
    effective_status: null,
    adaptation: "excluded",
    adaptation_reason: "Беспроводного доступа нет",
  }),
];

function setOf(over: Partial<MeasureSet> = {}): MeasureSet {
  return {
    state: "built",
    profile_id: "fstec-117",
    profile_short: "ФСТЭК №117",
    level_label: "Класс защищённости",
    classification: CLASS,
    adaptation: {
      id: "a1",
      version: 1,
      classification_id: "c1",
      profile_id: "fstec-117",
      level: "К2",
      level_label: "К2 — второй класс",
      status: "draft",
      created_at: "2026-11-04T10:00:00Z",
      created_by_name: "Иванова А. А.",
      edits: 1,
      updated_at: "2026-11-04T10:00:00Z",
      editor_ids: ["u2"],
      approved_at: null,
      approved_by_name: null,
      approval_comment: null,
      unverified_acknowledged: false,
      superseded_at: null,
      counts: null,
    },
    class_changed: false,
    rebuild_needed: false,
    plan_counts: null,
    stats: {
      total: bucket(),
      auto: bucket({ total: 1, unassessed: 0, excluded: 0, percent: 100 }),
      manual: bucket({ total: 1, implemented: 0, score: 0, percent: 0 }),
    },
    partial_weight: 0.5,
    groups: [{ code: "МРП", title: "Мероприятия", total: 3 }],
    counts: { total: 3, baseline: 3, added: 0, excluded: 1, compensated: 0 },
    unverified: 3,
    approve_blockers: [],
    ...over,
  };
}

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

const BASE = {
  "GET /projects": () => json([PROJECT]),
  "GET /objects/o1": () => json(OBJ),
  "GET /objects/o1/hosts": () => json([]),
};

it("без сформированного набора — план базового набора по классу, затем сборка", async () => {
  let built = false;
  const plan = {
    classification: CLASS,
    profile_id: "fstec-117",
    level: "К2",
    add: [{ measure_id: "КК", title: "Контроль конфигураций", group_code: "МРП", assessed: false }],
    remove: [],
    promote: [],
    reset: [],
    foreign: [],
    unchanged: 0,
    empty: false,
    changes: true,
  };
  const calls = fakeApi({
    ...BASE,
    "GET /me": () => json(METH),
    "GET /objects/o1/measure-set": () => json(built ? setOf() : setOf({ state: "not_built", adaptation: null, stats: null })),
    "GET /objects/o1/measures": () => json(MEASURES),
    "GET /objects/o1/adaptations": () => json([]),
    "POST /objects/o1/measures/rebuild": (init) => {
      built = JSON.parse(String(init?.body)).dry_run === false;
      return json(plan);
    },
  });
  renderAt("/objects/o1?tab=measures");

  fireEvent.click(await screen.findByRole("button", { name: /Сформировать базовый набор/ }));
  const dialog = await screen.findByRole("dialog");
  expect(await within(dialog).findByText("Войдут в набор")).toBeInTheDocument();
  fireEvent.click(within(dialog).getByRole("button", { name: "Сформировать" }));
  await waitFor(() =>
    expect(calls.filter((c) => c.path === "/objects/o1/measures/rebuild").map((c) => c.body)).toEqual([
      { dry_run: true },
      { dry_run: false },
    ]),
  );
  // Процент и исключённая мера с обоснованием.
  expect(await screen.findByText("50 %")).toBeInTheDocument();
  expect(screen.getByText("Исключена: Беспроводного доступа нет")).toBeInTheDocument();
});

it("исключение меры требует обоснования и уходит одним запросом", async () => {
  const calls = fakeApi({
    ...BASE,
    "GET /me": () => json(METH),
    "GET /objects/o1/measure-set": () => json(setOf()),
    "GET /objects/o1/measures": () => json(MEASURES),
    "GET /objects/o1/adaptations": () => json([]),
    "PATCH /object-measures/m2": () => json(MEASURES[1]),
  });
  renderAt("/objects/o1?tab=measures");

  fireEvent.click(await screen.findByText("Выявление угроз"));
  const drawer = await screen.findByRole("dialog");
  fireEvent.click(within(drawer).getByRole("radio", { name: "Исключить" }));
  fireEvent.change(within(drawer).getByLabelText("Обоснование исключения"), {
    target: { value: "Угрозы определены моделью угроз заказчика" },
  });
  fireEvent.click(within(drawer).getByRole("button", { name: "Сохранить адаптацию" }));
  await waitFor(() =>
    expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({
      adaptation: "excluded",
      adaptation_reason: "Угрозы определены моделью угроз заказчика",
    }),
  );
  // У методиста нет права ставить статус — блока оценки с полями нет.
  expect(within(drawer).queryByRole("button", { name: "Сохранить оценку" })).not.toBeInTheDocument();
});

it("утверждающий подтверждает несверенный справочник", async () => {
  const calls = fakeApi({
    ...BASE,
    "GET /me": () => json(BOSS),
    "GET /objects/o1/measure-set": () => json(setOf()),
    "GET /objects/o1/measures": () => json(MEASURES),
    "GET /objects/o1/adaptations": () => json([]),
    "POST /objects/o1/adaptation/approve": () => json({}),
  });
  renderAt("/objects/o1?tab=measures");

  fireEvent.click(await screen.findByRole("button", { name: /Утвердить/ }));
  const dialog = await screen.findByRole("dialog");
  const submit = within(dialog).getByRole("button", { name: "Утвердить" });
  expect(submit).toBeDisabled();
  fireEvent.click(within(dialog).getByRole("checkbox"));
  fireEvent.click(submit);
  await waitFor(() =>
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({
      comment: null,
      acknowledge_unverified: true,
      version: 1,
    }),
  );
});

it("свою версию адаптации утвердить нельзя", async () => {
  fakeApi({
    ...BASE,
    "GET /me": () => json({ ...METH, permissions: [...METH.permissions, "approve"] }),
    "GET /objects/o1/measure-set": () => json(setOf()),
    "GET /objects/o1/measures": () => json(MEASURES),
    "GET /objects/o1/adaptations": () => json([]),
  });
  renderAt("/objects/o1?tab=measures");
  expect(await screen.findByRole("button", { name: /Утвердить/ })).toBeDisabled();
});
