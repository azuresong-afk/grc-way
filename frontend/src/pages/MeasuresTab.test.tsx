import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
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
  permissions: [
    "view",
    "objects.edit",
    "classification.edit",
    "adaptation.edit",
  ],
};
const BOSS = {
  ...METH,
  id: "u9",
  display_name: "Смирнов С. С.",
  roles: ["viewer", "approve"],
  permissions: ["view", "approve"],
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
  classification: {
    id: "c1",
    result: "К2",
    short: "К2",
    result_label: "К2 — второй класс",
    status: "approved",
  },
};

const CLASS = {
  id: "c1",
  result: "К2",
  result_label: "К2 — второй класс",
  status: "approved",
};

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
    status_source: null,
    auto_status: null,
    auto_note: null,
    auto_snapshot_id: null,
    confirmed_at: null,
    confirmed_by_name: null,
    confirmed_status: null,
    confirm_comment: null,
    manual_evidence: 0,
    updated_at: "2026-11-04T10:00:00Z",
    ...over,
  };
}

const MEASURES = [
  measure({}),
  measure({
    id: "m2",
    measure_id: "ВУ",
    title: "Выявление угроз",
    method: "manual",
    checks: [],
    status: "unassessed",
    effective_status: "unassessed",
  }),
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
    snapshot: null,
    confirmed: 0,
    to_confirm: 1,
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
    add: [
      {
        measure_id: "КК",
        title: "Контроль конфигураций",
        group_code: "МРП",
        assessed: false,
      },
    ],
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
    "GET /objects/o1/measure-set": () =>
      json(
        built
          ? setOf()
          : setOf({ state: "not_built", adaptation: null, stats: null }),
      ),
    "GET /objects/o1/measures": () => json(MEASURES),
    "GET /objects/o1/adaptations": () => json([]),
    "POST /objects/o1/measures/rebuild": (init) => {
      built = JSON.parse(String(init?.body)).dry_run === false;
      return json(plan);
    },
  });
  renderAt("/objects/o1?tab=measures");

  fireEvent.click(
    await screen.findByRole("button", { name: /Сформировать базовый набор/ }),
  );
  const dialog = await screen.findByRole("dialog");
  expect(await within(dialog).findByText("Войдут в набор")).toBeInTheDocument();
  fireEvent.click(within(dialog).getByRole("button", { name: "Сформировать" }));
  await waitFor(() =>
    expect(
      calls
        .filter((c) => c.path === "/objects/o1/measures/rebuild")
        .map((c) => c.body),
    ).toEqual([{ dry_run: true }, { dry_run: false }]),
  );
  // Процент и исключённая мера с обоснованием.
  expect(await screen.findByText("50 %")).toBeInTheDocument();
  expect(
    screen.getByText("Исключена: Беспроводного доступа нет"),
  ).toBeInTheDocument();
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
  fireEvent.click(
    within(drawer).getByRole("button", { name: "Сохранить адаптацию" }),
  );
  await waitFor(() =>
    expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({
      adaptation: "excluded",
      adaptation_reason: "Угрозы определены моделью угроз заказчика",
    }),
  );
  // У методиста нет права ставить статус — блока оценки с полями нет.
  expect(
    within(drawer).queryByRole("button", { name: "Сохранить оценку" }),
  ).not.toBeInTheDocument();
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
    "GET /me": () =>
      json({ ...METH, permissions: [...METH.permissions, "approve"] }),
    "GET /objects/o1/measure-set": () => json(setOf()),
    "GET /objects/o1/measures": () => json(MEASURES),
    "GET /objects/o1/adaptations": () => json([]),
  });
  renderAt("/objects/o1?tab=measures");
  expect(
    await screen.findByRole("button", { name: /Утвердить/ }),
  ).toBeDisabled();
});

// ---------- Импорт прогона «Сканера» (1.9) ----------

const EXP = {
  ...METH,
  id: "u3",
  display_name: "Козлов К. К.",
  roles: ["assessor"],
  permissions: ["view", "assessment.edit", "evidence.upload", "scanner.import"],
};
const LINKED = { ...OBJ, scanner_engagement_id: 1 };

const SNAPSHOT = {
  id: "s2",
  number: 2,
  current: true,
  run_id: 8,
  run_name: "Повторный прогон",
  run_status: "partial",
  run_started_at: "2026-11-02T13:10:00Z",
  run_finished_at: "2026-11-02T14:30:05Z",
  selection: "latest" as const,
  profile_id: "fstec-117",
  level: "К2",
  adaptation_version: 1,
  percent: 72.2,
  counts: { passed: 13, failed: 5, na: 4, manual: 80 },
  summary: {
    measures: 24,
    implemented: 14,
    partial: 3,
    not_implemented: 2,
    unassessed: 5,
    applied: 20,
    kept_manual: 0,
  },
  hosts: 10,
  coverage_gaps: 11,
  source: "фикстура «Сканера»",
  imported_at: "2026-11-04T12:00:00Z",
  imported_by_name: "Козлов К. К.",
};

it("эксперт импортирует «последний завершённый» прогон", async () => {
  let imported = false;
  const calls = fakeApi({
    ...BASE,
    "GET /objects/o1": () => json(LINKED),
    "GET /me": () => json(EXP),
    "GET /objects/o1/measure-set": () =>
      json(setOf({ snapshot: imported ? SNAPSHOT : null })),
    "GET /objects/o1/measures": () => json(MEASURES),
    "GET /objects/o1/adaptations": () => json([]),
    "GET /objects/o1/scanner/runs": () =>
      json({
        engagement_id: 1,
        source: "фикстура «Сканера»",
        mode: "fixture",
        latest_id: 8,
        runs: [
          {
            id: 8,
            name: "Повторный прогон",
            status: "partial",
            started_at: null,
            finished_at: "2026-11-02T14:30:05Z",
            modules: [],
            error_message: null,
            snapshots: [],
          },
          {
            id: 7,
            name: "Плановый прогон",
            status: "done",
            started_at: null,
            finished_at: "2026-10-28T11:42:30Z",
            modules: [],
            error_message: null,
            snapshots: [1],
          },
        ],
      }),
    "POST /objects/o1/scanner/import": () => {
      imported = true;
      return json({ snapshot: SNAPSHOT, applied: 20, kept_manual: 0 }, 201);
    },
  });
  renderAt("/objects/o1?tab=measures");

  expect(
    await screen.findByText(/Прогоны ещё не импортированы/),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /Импортировать прогон/ }));
  const dialog = await screen.findByRole("dialog");
  expect(
    await within(dialog).findByText(/сейчас это прогон №8/),
  ).toBeInTheDocument();
  expect(within(dialog).getByText(/уже в снимке №1/)).toBeInTheDocument();
  fireEvent.click(
    within(dialog).getByRole("button", { name: /^Импортировать$/ }),
  );
  await waitFor(() =>
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({
      run_id: "latest",
    }),
  );
  expect(
    await screen.findByText(/Снимок №2 сохранён: статусов изменено — 20/),
  ).toBeInTheDocument();
  expect(screen.getByText("Снимок №2")).toBeInTheDocument();
  expect(screen.getByText("72 %")).toBeInTheDocument();
});

it("карточка меры показывает нарушения по хостам и принимает предложение «Сканера»", async () => {
  const manual = measure({
    status: "partial",
    effective_status: "partial",
    status_source: "manual",
    auto_status: "not_implemented",
    auto_note: "Нарушения на всех проверенных хостах объекта (7 хостов)",
    auto_snapshot_id: "s2",
  });
  const calls = fakeApi({
    ...BASE,
    "GET /objects/o1": () => json(LINKED),
    "GET /me": () => json(EXP),
    "GET /objects/o1/measure-set": () => json(setOf({ snapshot: SNAPSHOT })),
    "GET /objects/o1/measures": () => json([manual, ...MEASURES.slice(1)]),
    "GET /objects/o1/adaptations": () => json([]),
    "GET /object-measures/m1/evidence": () =>
      json([
        {
          id: "e1",
          kind: "scanner",
          status: "not_implemented",
          summary: "Нарушения на всех проверенных хостах объекта (7 хостов)",
          snapshot: SNAPSHOT,
          created_at: "2026-11-04T12:00:00Z",
          created_by_name: "Козлов К. К.",
          data: {
            status: "not_implemented",
            reason: "failed_all",
            note: "",
            control_status: "failed",
            hosts: ["10.10.1.10", "10.10.3.103"],
            checked: ["10.10.1.10"],
            failed: ["10.10.1.10"],
            unchecked: [
              {
                host: "10.10.3.103",
                reason: "аудит конфигурации: хост недоступен",
              },
            ],
            not_applicable: [],
            outside_failed: ["10.20.0.15"],
            run: {
              id: 8,
              name: null,
              status: "partial",
              finished_at: null,
              percent: 72.2,
            },
            failed_hosts: [
              {
                host: "10.10.1.10",
                checks: [
                  {
                    id: "session_timeout",
                    failures: [{ kind: "fact", title: "правило x — fail" }],
                    more: 0,
                  },
                ],
              },
            ],
            recommendations: [
              {
                check: "session_timeout",
                title: "Тайм-аут сеанса",
                remediation: "Задать TMOUT",
                doc: null,
              },
            ],
            host_counts: {},
          },
        },
      ]),
    "PATCH /object-measures/m1": () =>
      json({ ...manual, status: "not_implemented", status_source: "auto" }),
  });
  renderAt("/objects/o1?tab=measures");

  expect(
    await screen.findByText("«Сканер»: Не реализована"),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByText("Контроль конфигураций"));
  const drawer = await screen.findByRole("dialog");
  expect(await within(drawer).findByText("10.10.3.103")).toBeInTheDocument();
  expect(within(drawer).getByText(/правило x — fail/)).toBeInTheDocument();
  expect(within(drawer).getByText("Задать TMOUT")).toBeInTheDocument();
  expect(within(drawer).getByText(/Нарушения вне объекта/)).toBeInTheDocument();
  fireEvent.click(
    within(drawer).getByRole("button", { name: "Принять предложение" }),
  );
  await waitFor(() =>
    expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({
      use_auto: true,
    }),
  );
});

// ---------- Ручная оценка (1.10) ----------

const VU = MEASURES[1];

function manualEvidence(over: Record<string, unknown> = {}) {
  return {
    id: "e5",
    kind: "file",
    status: null,
    summary: "Положение о защите информации",
    data: { category: "document" },
    snapshot: null,
    file: {
      id: "f1",
      name: "Положение.pdf",
      ext: "pdf",
      mime: "application/pdf",
      size: 245760,
      sha256: "ab".repeat(32),
    },
    created_at: "2026-11-04T12:00:00Z",
    created_by_name: "Козлов К. К.",
    withdrawn_at: null,
    withdrawn_by_name: null,
    withdraw_reason: null,
    in_confirmation: false,
    ...over,
  };
}

it("эксперт прикладывает файл к организационной мере", async () => {
  let sent: FormData | null = null;
  fakeApi({
    ...BASE,
    "GET /me": () => json(EXP),
    "GET /objects/o1/measure-set": () => json(setOf()),
    "GET /objects/o1/measures": () => json(MEASURES),
    "GET /objects/o1/adaptations": () => json([]),
    "GET /object-measures/m2/evidence": () => json([]),
    "POST /object-measures/m2/evidence": (init) => {
      sent = init?.body as FormData;
      return json(manualEvidence(), 201);
    },
  });
  renderAt("/objects/o1?tab=measures");

  fireEvent.click(await screen.findByText("Выявление угроз"));
  const drawer = await screen.findByRole("dialog");
  expect(
    await within(drawer).findByText(/Доказательств нет/),
  ).toBeInTheDocument();
  // Без статуса подтверждать нечего.
  expect(
    within(drawer).getByText("Сначала поставьте статус меры."),
  ).toBeInTheDocument();

  fireEvent.click(within(drawer).getByRole("button", { name: /Добавить/ }));
  const submit = within(drawer).getByRole("button", {
    name: "Добавить доказательство",
  });
  expect(submit).toBeDisabled();
  const file = new File(["%PDF-1.7"], "Положение.pdf", {
    type: "application/pdf",
  });
  fireEvent.change(within(drawer).getByLabelText("Файл доказательства"), {
    target: { files: [file] },
  });
  fireEvent.change(within(drawer).getByLabelText("Что подтверждает"), {
    target: { value: "Положение о защите информации" },
  });
  fireEvent.click(submit);
  await waitFor(() => expect(sent).not.toBeNull());
  const form = sent as unknown as FormData;
  expect(form.get("kind")).toBe("file");
  expect(form.get("category")).toBe("document");
  expect(form.get("summary")).toBe("Положение о защите информации");
  expect((form.get("file") as File).name).toBe("Положение.pdf");
});

it("интервью уходит JSON с датой и опрошенными", async () => {
  const calls = fakeApi({
    ...BASE,
    "GET /me": () => json(EXP),
    "GET /objects/o1/measure-set": () => json(setOf()),
    "GET /objects/o1/measures": () => json(MEASURES),
    "GET /objects/o1/adaptations": () => json([]),
    "GET /object-measures/m2/evidence": () => json([]),
    "POST /object-measures/m2/evidence": () =>
      json(manualEvidence({ kind: "interview", file: null }), 201),
  });
  renderAt("/objects/o1?tab=measures");

  fireEvent.click(await screen.findByText("Выявление угроз"));
  const drawer = await screen.findByRole("dialog");
  fireEvent.click(
    await within(drawer).findByRole("button", { name: /Добавить/ }),
  );
  fireEvent.click(within(drawer).getByRole("radio", { name: "Интервью" }));
  fireEvent.change(within(drawer).getByLabelText("Дата"), {
    target: { value: "2026-11-02" },
  });
  fireEvent.change(within(drawer).getByLabelText("Кого опрашивали"), {
    target: { value: "Петров П. П., администратор" },
  });
  fireEvent.change(within(drawer).getByLabelText("Что подтверждает"), {
    target: { value: "Журнал инцидентов ведётся" },
  });
  fireEvent.click(
    within(drawer).getByRole("button", { name: "Добавить доказательство" }),
  );
  await waitFor(() =>
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({
      kind: "interview",
      summary: "Журнал инцидентов ведётся",
      held_on: "2026-11-02",
      participants: "Петров П. П., администратор",
      place: null,
      details: null,
    }),
  );
});

it("мера с доказательством подтверждается, отзыв предупреждает о снятии подтверждения", async () => {
  const assessed = {
    ...VU,
    status: "implemented" as const,
    effective_status: "implemented" as const,
    manual_evidence: 1,
  };
  const calls = fakeApi({
    ...BASE,
    "GET /me": () => json(EXP),
    "GET /objects/o1/measure-set": () => json(setOf()),
    "GET /objects/o1/measures": () => json([MEASURES[0], assessed]),
    "GET /objects/o1/adaptations": () => json([]),
    "GET /object-measures/m2/evidence": () =>
      json([manualEvidence({ in_confirmation: true })]),
    "POST /object-measures/m2/confirm": () =>
      json({ ...assessed, confirmed_at: "2026-11-04T13:00:00Z" }),
    "POST /evidence/e5/withdraw": () => json(manualEvidence()),
  });
  renderAt("/objects/o1?tab=measures");

  fireEvent.click(await screen.findByText("Выявление угроз"));
  const drawer = await screen.findByRole("dialog");
  expect(await within(drawer).findByText("Положение.pdf")).toBeInTheDocument();
  expect(within(drawer).getByText("240 КБ")).toBeInTheDocument();
  fireEvent.click(
    within(drawer).getByRole("button", { name: /Подтвердить «Реализована»/ }),
  );
  await waitFor(() =>
    expect(
      calls.find((c) => c.path === "/object-measures/m2/confirm")?.body,
    ).toEqual({ status: "implemented", comment: null }),
  );

  fireEvent.click(within(drawer).getByRole("button", { name: /Отозвать/ }));
  const dialogs = await screen.findAllByRole("dialog");
  const modal = dialogs[dialogs.length - 1] as HTMLElement;
  expect(
    within(modal).getByText(/подтверждение будет снято/),
  ).toBeInTheDocument();
  const go = within(modal).getByRole("button", { name: "Отозвать" });
  expect(go).toBeDisabled();
  fireEvent.change(within(modal).getByLabelText("Причина"), {
    target: { value: "Не та редакция" },
  });
  fireEvent.click(go);
  await waitFor(() =>
    expect(calls.find((c) => c.path === "/evidence/e5/withdraw")?.body).toEqual(
      { reason: "Не та редакция" },
    ),
  );
});

it("подтверждённая мера видна в таблице, фильтр «Ждут подтверждения»", async () => {
  fakeApi({
    ...BASE,
    "GET /me": () => json(EXP),
    "GET /objects/o1/measure-set": () =>
      json(setOf({ confirmed: 1, to_confirm: 1 })),
    "GET /objects/o1/measures": () =>
      json([
        measure({
          confirmed_at: "2026-11-04T13:00:00Z",
          confirmed_status: "implemented",
          confirmed_by_name: "Козлов К. К.",
        }),
        { ...VU, status: "not_implemented", manual_evidence: 2 },
      ]),
    "GET /objects/o1/adaptations": () => json([]),
  });
  renderAt("/objects/o1?tab=measures");

  expect(await screen.findByText("подтверждена")).toBeInTheDocument();
  expect(
    screen.getByText(/подтверждено 1 · ждут подтверждения 1/),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Ждут подтверждения" }));
  expect(screen.queryByText("Контроль конфигураций")).not.toBeInTheDocument();
  expect(screen.getByText("Выявление угроз")).toBeInTheDocument();
});
