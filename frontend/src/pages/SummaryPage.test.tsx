import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import type { ProjectSummary } from "../lib/summary";
import { fakeApi, json } from "../test/fakeApi";

const VIEWER = {
  id: "u4",
  username: "viewer",
  display_name: "Орлова О. О.",
  roles: ["viewer"],
  permissions: ["view"],
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
  scanner_engagement_id: 1,
  platform_project_id: null,
  created_at: "2026-11-01T10:00:00Z",
  members: [],
};

const bucket = (over: Partial<Record<string, number>> = {}) => ({
  total: 10,
  implemented: 5,
  partial: 2,
  not_implemented: 1,
  unassessed: 2,
  excluded: 0,
  not_applicable: 0,
  compensated: 0,
  score: 6,
  percent: 60,
  ...over,
});

const PROGRESS = {
  percent_all: 47.6,
  percent_assessed: 67.4,
  total: 103,
  assessed_total: 29,
  manual_unassessed: 74,
  note: "Главная платформы считает процент только по оценённым мерам (67,4 %): 74 неоценённые организационные меры в расчёт не входят.",
  actions: [
    { code: "assess_manual" as const, count: 74, gain: 71.8, label: "Оценить 74 организационные меры (интервью, осмотр, документ)" },
    { code: "fix_failed" as const, count: 9, gain: 8.7, label: "Устранить 9 нереализованных мер" },
  ],
};

const SUMMARY: ProjectSummary = {
  project_id: "p1",
  name: "Аттестация ГИС",
  client: "ГБУ «Центр»",
  partial_weight: 0.5,
  kpi: {
    objects: 2,
    hosts: 12,
    objects_assessed: 1,
    stats: {
      total: bucket({ percent: 47.6 }),
      auto: bucket({ percent: 64.2 }),
      manual: bucket({ percent: 1.3 }),
    },
    progress: PROGRESS,
    nonconformities: 9,
    manual_pending: 74,
    to_confirm: 18,
    confirmed: 1,
    unverified: 96,
    unverified_tables: ["117", "21"],
    szi: { total: 5, bad: 1, expiring: 1, check: 0, uncertified: 0 },
    szi_expiry_days: 90,
  },
  objects: [
    {
      id: "o1",
      name: "ГИС «Учёт»",
      kind: "gis",
      regime: "117",
      status: "active",
      host_count: 10,
      classification: { id: "c1", result: "К2", short: "К2", result_label: "Класс 2", status: "approved" },
      class_unverified: true,
      state: "built",
      stats: {
        total: bucket({ percent: 47.6 }),
        auto: bucket({ percent: 64.2 }),
        manual: bucket({ percent: 1.3 }),
      },
      progress: PROGRESS,
      adaptation: { version: 1, status: "approved" },
      snapshot: {
        id: "s2",
        number: 2,
        run_id: 7,
        run_name: "Плановый",
        run_finished_at: "2026-11-02T14:30:00Z",
        imported_at: "2026-11-04T10:00:00Z",
        coverage_gaps: 0,
      },
      snapshots: 2,
      measures: 103,
      nonconformities: 9,
      manual_pending: 74,
      to_confirm: 18,
      confirmed: 1,
      unverified: 96,
      szi: { total: 5, bad: 1, expiring: 1, check: 0, uncertified: 0 },
    },
    {
      id: "o2",
      name: "ИСПДн «Бухгалтерия»",
      kind: "ispdn",
      regime: "21",
      status: "active",
      host_count: 2,
      classification: null,
      class_unverified: false,
      state: "no_class",
      stats: null,
      progress: null,
      adaptation: null,
      snapshot: null,
      snapshots: 0,
      measures: 0,
      nonconformities: 0,
      manual_pending: 0,
      to_confirm: 0,
      confirmed: 0,
      unverified: 0,
      szi: { total: 0, bad: 0, expiring: 0, check: 0, uncertified: 0 },
    },
  ],
};

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  localStorage.clear();
  sessionStorage.setItem(TOKEN_KEY, "tok");
});
afterEach(() => vi.unstubAllGlobals());

it("сводка: показатели проекта, «требует сверки» и таблица объектов", async () => {
  fakeApi({
    "GET /me": () => json(VIEWER),
    "GET /projects": () => json([PROJECT]),
    "GET /health/ready": () => json({ status: "ok" }),
    "GET /projects/p1/summary": () => json(SUMMARY),
  });
  renderAt("/summary");

  expect(await screen.findByText("Реализация мер по проекту")).toBeInTheDocument();
  expect(screen.getAllByText("48 %")[0]).toHaveClass("kpi-value");
  expect(screen.getByText("авто 64 % · вручную 1 %")).toBeInTheDocument();
  expect(screen.getByText("12 хостов · в проценте 1")).toBeInTheDocument();
  const warn = screen.getByRole("status");
  expect(warn).toHaveTextContent("Таблицы классификации №117, №21 не сверены методистом");
  expect(warn).toHaveTextContent("96 мер в наборах объектов");

  const gis = screen.getByRole("link", { name: "ГИС «Учёт»" });
  expect(gis).toHaveAttribute("href", "/objects/o1?tab=measures");
  const row = gis.closest("tr")!;
  expect(within(row).getByText("К2")).toBeInTheDocument();
  expect(within(row).getByText("Требует сверки")).toBeInTheDocument();
  expect(within(row).getByText("№2 · прогон №7")).toBeInTheDocument();
  expect(within(row).getByText("ручной оценки: 74")).toBeInTheDocument();
  expect(within(row).getByText("недействительны: 1").closest("a")).toHaveAttribute("href", "/objects/o1?tab=szi");
  expect(within(row).getByText("истекают: 1")).toBeInTheDocument();
  expect(screen.getByText("недействительны 1 · истекают за 90 дн. 1")).toBeInTheDocument();

  // Оба процента, причина разницы и что сделать.
  expect(screen.getByTestId("percent-assessed")).toHaveTextContent("по оценённым мерам, как на Главной: 67 %");
  const how = screen.getByRole("region", { name: "Как поднять процент" });
  expect(how).toHaveTextContent("по всем мерам 48 % · по оценённым 67 %");
  expect(how).toHaveTextContent("74 неоценённые организационные меры в расчёт не входят");
  const steps = within(how).getAllByRole("listitem");
  expect(steps[0]).toHaveTextContent("Оценить 74 организационные меры (интервью, осмотр, документ)до +72 п. п.");
  expect(steps[1]).toHaveTextContent("Устранить 9 нереализованных мердо +9 п. п.");
  expect(within(row).getByText("по оценённым 67 %")).toBeInTheDocument();

  const pdn = screen.getByRole("link", { name: "ИСПДн «Бухгалтерия»" }).closest("tr")!;
  expect(within(pdn).getByText("Класс не утверждён")).toBeInTheDocument();
});

it("Ctrl+K: разделы, поиск записей, переход к мере по стрелкам и Enter", async () => {
  const calls = fakeApi({
    "GET /me": () => json(VIEWER),
    "GET /projects": () => json([PROJECT]),
    "GET /health/ready": () => json({ status: "ok" }),
    "GET /projects/p1/summary": () => json(SUMMARY),
    "GET /search": (_init, url) =>
      json({
        q: url.searchParams.get("q"),
        items: [
          {
            kind: "object",
            id: "o1",
            title: "ГИС «Учёт»",
            subtitle: "Аттестация ГИС",
            project_id: "p1",
            path: "/objects/o1?project=p1",
            url: "/grc/objects/o1?project=p1",
          },
          {
            kind: "measure",
            id: "m8",
            title: "УПД.8 · Блокирование сеанса",
            subtitle: "ГИС «Учёт»",
            project_id: "p1",
            path: "/objects/o1?project=p1&tab=measures&measure=m8",
            url: "/grc/objects/o1?project=p1&tab=measures&measure=m8",
          },
        ],
      }),
    "GET /objects/o1": () => json({ detail: "нет" }, 404),
  });
  renderAt("/summary");
  await screen.findByText("Реализация мер по проекту");

  fireEvent.keyDown(document, { key: "л", code: "KeyK", ctrlKey: true }); // русская раскладка
  const dialog = await screen.findByRole("dialog", { name: "Быстрый поиск" });
  const input = within(dialog).getByRole("combobox", { name: "Что найти" });
  expect(input).toHaveFocus();
  // Без запроса — только разделы, по правам: наблюдателю администрирование не показано.
  expect(within(dialog).getByRole("option", { name: /Объекты/ })).toBeInTheDocument();
  expect(within(dialog).queryByRole("option", { name: /Журнал аудита/ })).not.toBeInTheDocument();

  fireEvent.change(input, { target: { value: "упд" } });
  const measure = await within(dialog).findByRole("option", { name: /УПД\.8/ });
  expect(within(dialog).getByText("Меры объектов")).toBeInTheDocument();
  expect(calls.some((c) => c.path === "/search")).toBe(true);

  fireEvent.keyDown(input, { key: "ArrowDown" });
  expect(measure).toHaveAttribute("aria-selected", "true");
  fireEvent.keyDown(input, { key: "Enter" });
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Быстрый поиск" })).not.toBeInTheDocument());
  await waitFor(() => expect(calls.some((c) => c.path === "/objects/o1")).toBe(true));
});

it("Esc закрывает палитру; кнопка «Поиск» её открывает", async () => {
  fakeApi({
    "GET /me": () => json(VIEWER),
    "GET /projects": () => json([PROJECT]),
    "GET /health/ready": () => json({ status: "ok" }),
    "GET /projects/p1/summary": () => json(SUMMARY),
  });
  renderAt("/summary");
  fireEvent.click(await screen.findByRole("button", { name: "Поиск" }));
  const input = await screen.findByRole("combobox", { name: "Что найти" });
  fireEvent.change(input, { target: { value: "журнал" } });
  expect(screen.getByText(/Ничего не найдено|Ищем/)).toBeInTheDocument();
  fireEvent.keyDown(input, { key: "Escape" });
  expect(screen.queryByRole("dialog", { name: "Быстрый поиск" })).not.toBeInTheDocument();
});
