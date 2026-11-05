import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import type { Definition, Methodology, Outcome, RefDocument } from "../lib/vulnCriticality";
import { deadlineText } from "../lib/vulnCriticality";
import { fakeApi, json } from "../test/fakeApi";

const ME = {
  id: "u2",
  username: "m",
  display_name: "Иванова А. А.",
  roles: ["methodologist", "admin"],
  permissions: ["view", "refs.verify", "refs.manage"],
};

const EX1 = { cvss: "8.8", K: ["K2"], L: ["L3"], P: ["P1"], E: ["E3"], H: ["H2"] };

const DEF: Definition = {
  formula: { text: "V = I_cvss × I_infr × (I_at + I_imp)", source: { clause: "12" } },
  rounding: { digits: 2, note: "Как в примерах приложения." },
  cvss: { version: "3.1", min: 0, max: 10 },
  groups: [
    { code: "infr", symbol: "I_infr", title: "Влияние", formula: "I_infr = k × K + l × L + p × P" },
    { code: "at", symbol: "I_at", title: "Эксплуатация", formula: "I_at = e × E" },
    { code: "imp", symbol: "I_imp", title: "Последствия", formula: "I_imp = h × H" },
  ],
  indicators: [
    {
      code: "K",
      group: "infr",
      weight_symbol: "k",
      weight: 0.5,
      title: "Тип компонента",
      multiple: "max",
      source: { clause: "14, 15", table: "1", row: "1" },
      values: [
        { code: "K1", score: 1.1, title: "Важные процессы" },
        { code: "K2", score: 0.9, title: "Уязвимости подвержены межсетевые экраны" },
      ],
    },
    { code: "L", group: "infr", weight_symbol: "l", weight: 0.2, title: "Количество", multiple: "max", values: [{ code: "L3", score: 0.6, title: "10-50%" }] },
    { code: "P", group: "infr", weight_symbol: "p", weight: 0.3, title: "Периметр", multiple: "single", values: [{ code: "P1", score: 1.1, title: "Доступно из сети «Интернет»" }] },
    { code: "E", group: "at", weight_symbol: "e", weight: 1, title: "Эксплуатация", multiple: "max", values: [{ code: "E3", score: 0.1, title: "Нет сведений" }] },
    { code: "H", group: "imp", weight_symbol: "h", weight: 1, title: "Последствия", multiple: "max", values: [{ code: "H2", score: 0.5, title: "Повышение привилегий" }] },
  ],
  levels: [
    { code: "critical", title: "Критический", condition: "V > 8,0", deadline: { value: 24, unit: "hours" } },
    { code: "high", title: "Высокий", condition: "5,0 ≤ V ≤ 8,0", deadline: { value: 7, unit: "days" } },
    { code: "medium", title: "Средний", condition: "2,0 ≤ V < 5,0", deadline: { value: 4, unit: "weeks" } },
    { code: "low", title: "Низкий", condition: "V < 2,0", deadline: { value: 4, unit: "months" } },
  ],
  certified_szi: { level: "critical", text: "Критический уровень для сертифицированных СЗИ.", source: { clause: "4" } },
  compensating_measures: { source: { clause: "25" }, items: [{ code: "CM3", title: "Резервирование компонентов системы" }] },
  examples: [
    {
      code: "example-1",
      title: "Пример 1: BDU:2025-01611",
      inputs: EX1,
      expected: { v: "4.75", level: "medium" },
    },
  ],
};

const OUTCOME: Outcome = {
  v: "4.75",
  v_exact: "4.752",
  level: { code: "medium", title: "Средний", condition: "2,0 ≤ V < 5,0", deadline: { value: 4, unit: "weeks" } },
  level_by_v: null,
  groups: { infr: "0.9", at: "0.1", imp: "0.5" },
  cvss: "8.8",
  certified_szi: false,
  trace: [
    { indicator: "cvss", title: "CVSS 3.1", score: "8.8" },
    { indicator: "K", title: "Тип компонента", weight: "0.5", score: "0.9", product: "0.45", value: "K2", value_title: "Уязвимости подвержены межсетевые экраны" },
  ],
};

const M: Methodology = {
  id: "fstec-2025",
  title: "Методика оценки уровня критичности уязвимостей",
  version: "2025-06-30-1",
  revision: 1,
  origin: "official",
  source: { document: "Методика (утв. ФСТЭК России 30.06.2025)", note: "Текст загружен." },
  verified: false,
  verified_by_name: null,
  verified_at: null,
  updated_at: "2026-11-05T00:00:00Z",
  definition: DEF,
  definition_hash: "x",
  examples: [{ code: "example-1", title: "Пример 1: BDU:2025-01611", inputs: EX1, expected: { v: "4.75" }, outcome: OUTCOME, reproduced: true }],
  revisions: [],
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

it("сроки п. 21 — в родительном падеже", () => {
  expect(deadlineText({ value: 24, unit: "hours" })).toBe("до 24 часов");
  expect(deadlineText({ value: 7, unit: "days" })).toBe("до 7 дней");
  expect(deadlineText({ value: 4, unit: "weeks" })).toBe("до 4 недель");
  expect(deadlineText({ value: 4, unit: "months" })).toBe("до 4 месяцев");
  expect(deadlineText({ value: 1, unit: "days" })).toBe("до 1 дня");
});

it("критичность: таблицы, пример приложения в калькуляторе, сверка", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  const calls = fakeApi({
    "GET /me": () => json(ME),
    "GET /projects": () => json([]),
    "GET /refs/vuln-criticality": () => json([M]),
    "GET /refs/vuln-criticality/fstec-2025": () => json(M),
    "POST /refs/vuln-criticality/fstec-2025/calculate": () =>
      json({ methodology_id: "fstec-2025", version: M.version, revision: 1, verified: false, outcome: OUTCOME }),
    "POST /refs/vuln-criticality/fstec-2025/verify": () =>
      json({ ...M, verified: true, verified_by_name: "Петров П. П.", verified_at: "2026-11-05T01:00:00Z" }),
  });
  renderAt("/refs/vuln-criticality");

  expect(await screen.findByText(/Таблица 1\. Весовые коэффициенты/)).toBeInTheDocument();
  // Итог таблицы 1 = вес × оценка: 0,5 × 1,1 = 0,55.
  const row = screen.getByText("Важные процессы").closest("tr")!;
  expect(within(row).getByText("0,55")).toBeInTheDocument();
  expect(screen.getByText("до 24 часов")).toBeInTheDocument();
  expect(screen.getByText("Воспроизводится")).toBeInTheDocument();
  expect(screen.getByText("Резервирование компонентов системы")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Пример 1" }));
  expect(screen.getByRole("button", { name: /K2 · 0,9/ })).toHaveAttribute("aria-pressed", "true");
  fireEvent.click(screen.getByRole("button", { name: /Рассчитать/ }));
  const result = await screen.findByLabelText("Результат расчёта");
  expect(within(result).getByText("4,75")).toBeInTheDocument();
  expect(within(result).getByText(/V = 8,8 × 0,9 × \(0,1 \+ 0,5\)/)).toBeInTheDocument();
  const sent = calls.find((c) => c.path.endsWith("/calculate"))?.body as { inputs: Record<string, unknown> };
  expect(sent.inputs).toMatchObject({ cvss: "8.8", K: ["K2"], P: ["P1"], certified_szi: false });

  fireEvent.click(screen.getByRole("button", { name: /Сверено с текстом/ }));
  await waitFor(() => expect(screen.getByText(/Сверено методистом: Петров П. П./)).toBeInTheDocument());
});

it("нормативные документы: Методика 2022 не применяется и заменена", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  const base = { issuer: "ФСТЭК России", number: null, url: null, origin: "official", verified: false, verified_by_name: null, verified_at: null, revision: 1, updated_at: "2026-11-05T00:00:00Z" };
  const docs: RefDocument[] = [
    { ...base, code: "fstec-vuln-2025", short: "Методика критичности уязвимостей 2025", title: "Методика", issued: "2025-06-30", status: "active", replaced_by: null, replaces: ["fstec-vuln-2022"], source: { note: "Текст загружен" } },
    { ...base, code: "fstec-vuln-2022", short: "Методика критичности уязвимостей 2022", title: "Методика", issued: "2022-10-28", status: "not_applicable", replaced_by: "fstec-vuln-2025", replaces: [], source: { document: "Методика 2025", clause: "6" } },
  ];
  fakeApi({
    "GET /me": () => json(ME),
    "GET /projects": () => json([]),
    "GET /refs/documents": () => json(docs),
    "GET /refs/documents/fstec-vuln-2022": () => json({ ...docs[1], revisions: [] }),
  });
  renderAt("/refs/documents");

  const row = (await screen.findByRole("button", { name: "Методика критичности уязвимостей 2022" })).closest("tr")!;
  expect(within(row).getByText("Не применяется")).toBeInTheDocument();
  expect(within(row).getByText(/заменён: Методика критичности уязвимостей 2025/)).toBeInTheDocument();
  expect(within(row).getByText("Методика 2025, п. 6")).toBeInTheDocument();
  expect(within(row).getByText(/от 28\.10\.2022/)).toBeInTheDocument();
});
