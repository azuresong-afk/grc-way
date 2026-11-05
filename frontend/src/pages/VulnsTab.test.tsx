import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import type { ObjectFull } from "../lib/objects";
import type { Methodology } from "../lib/vulnCriticality";
import type { Assessment, Register, VulnDetail, VulnRow } from "../lib/vulnRegister";
import { fakeApi, json } from "../test/fakeApi";

const EXP = {
  id: "u3",
  username: "exp",
  display_name: "Козлов К. К.",
  roles: ["assessor"],
  permissions: ["view", "assessment.edit", "evidence.upload", "scanner.import"],
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
  purpose: null,
  boundaries: null,
  interconnections: [],
  responsible: [],
  created_at: "2026-11-04T10:00:00Z",
  scanner_synced_at: null,
  scanner_engagement_id: 1,
  segments: [],
};

const ASSESSMENT: Assessment = {
  id: "a1",
  number: 1,
  v: "8.47",
  level: "critical",
  level_title: "Критический",
  assessed_at: "2026-11-01T10:00:00Z",
  assessed_by_name: "Козлов К. К.",
  deadline_at: "2026-11-02T10:00:00Z",
  deadline_from: 1,
  overdue: true,
  trigger: "choices",
  trigger_title: "выбор специалиста",
  reasons: ["первая оценка"],
  hosts: ["10.10.2.5"],
  inputs: { cvss: "9.8", K: ["K1"], L: ["L1"], P: ["P1"], E: ["E2"], H: ["H1"] },
  outcome: {
    v: "8.47",
    v_exact: "8.4672",
    level: { code: "critical", title: "Критический", condition: "V > 8,0", deadline: { value: 24, unit: "hours" } },
    level_by_v: null,
    groups: { infr: "1.08", at: "0.3", imp: "0.5" },
    cvss: "9.8",
    certified_szi: false,
    trace: [
      {
        indicator: "cvss",
        title: "Уровень опасности уязвимости по CVSS 3.1",
        score: "9.8",
        basis: "Базовая оценка CVSS 3.1 из БДУ (BDU:2025-03219)",
        basis_kind: "bdu",
        source: { clause: "13" },
      },
      {
        indicator: "L",
        title: "Количество уязвимых компонентов",
        weight: "0.2",
        value: "L1",
        value_title: "Более 70%",
        score: "1",
        product: "0.2",
        basis: "Сервер: 4 из 5 (80 %) → L1",
        basis_kind: "inventory",
        source: { clause: "14", table: "1", row: "2" },
      },
    ],
  },
  details: {},
  methodology_id: "fstec-2025",
  methodology_version: "2025-06-30-3",
  methodology_revision: 2,
  snapshot_number: 1,
};

const row = (over: Partial<VulnRow>): VulnRow => ({
  id: "v1",
  bdu_id: "BDU:2025-03219",
  title: "ingress-nginx: выполнение произвольного кода",
  origin: "scanner",
  manual_source: null,
  manual_source_title: null,
  cve_ids: ["CVE-2025-1974"],
  hosts: ["10.10.2.5"],
  scanner_hosts: ["10.10.2.5"],
  manual_hosts: [],
  last_seen_snapshot: 1,
  bdu_known: true,
  state: "current",
  state_title: "Оценка актуальна",
  missing: [],
  stale_reasons: [],
  preview: null,
  current: null,
  assessments: 0,
  updated_at: "2026-11-01T10:00:00Z",
  ...over,
});

const CURRENT = row({ current: ASSESSMENT, assessments: 1 });
const INCOMPLETE = row({
  id: "v2",
  bdu_id: "BDU:2024-04835",
  title: "OpenSSH: состояние гонки",
  state: "incomplete",
  state_title: "Не хватает данных",
  missing: [{ indicator: "H", text: "выберите последствия эксплуатации уязвимости (показатель H, п. 17)", addresses: [] }],
});

const REGISTER: Register = {
  methodology: { id: "fstec-2025", version: "2025-06-30-3", revision: 2, verified: false },
  snapshot: { id: "s1", number: 1, imported_at: "2026-11-01T09:00:00Z", findings_loaded: true },
  counts: {
    total: 2,
    current: 1,
    stale: 0,
    not_assessed: 0,
    incomplete: 1,
    not_detected: 0,
    critical: 1,
    high: 0,
    medium: 0,
    low: 0,
    overdue: 1,
  },
  items: [CURRENT, INCOMPLETE],
};

const detail = (r: VulnRow, history: Assessment[]): VulnDetail => ({
  ...r,
  description: null,
  comment: null,
  choices: { cvss: null, e: [], h: [], certified_szi: false },
  findings: [],
  bdu: null,
  proposal: {
    inputs: {},
    hosts: r.hosts,
    missing: r.missing,
    complete: !r.missing.length,
    cvss: {
      target_version: "3.1",
      options: [],
      choice: null,
      score: "8.1",
      version: "3.1",
      source: "bdu",
      fallback: false,
      basis: null,
    },
    exploitation: { indicator: "E", bdu: "E2", chosen: [], values: ["E2"] },
    outcome: null,
    notes: [],
  },
  history,
  created_at: "2026-11-01T10:00:00Z",
  created_by_name: "«Сканер», снимок №1",
  updated_by_name: null,
});

const METHODOLOGY = {
  id: "fstec-2025",
  title: "Методика",
  version: "2025-06-30-3",
  revision: 2,
  origin: "official",
  source: {},
  verified: false,
  verified_by_name: null,
  verified_at: null,
  updated_at: "2026-11-01T10:00:00Z",
  definition_hash: "h",
  examples: [],
  revisions: [],
  definition: {
    formula: { text: "V" },
    cvss: { version: "3.1", min: 0, max: 10 },
    groups: [],
    levels: [],
    indicators: [
      {
        code: "E",
        group: "at",
        weight: 1,
        title: "Эксплуатация уязвимости",
        multiple: "max",
        bdu: "exploitation",
        values: [
          { code: "E1", score: 0.6, title: "Эксплуатируется в реальных атаках" },
          { code: "E2", score: 0.3, title: "Имеются сведения о наличии эксплойта" },
          { code: "E3", score: 0.1, title: "Отсутствуют сведения" },
        ],
      },
      {
        code: "H",
        group: "imp",
        weight: 1,
        title: "Последствия",
        multiple: "max",
        values: [
          { code: "H1", score: 0.5, title: "Выполнение произвольного кода" },
          { code: "H7", score: 0.26, title: "Отказ в обслуживании" },
        ],
      },
    ],
  },
} as unknown as Methodology;

function renderAt(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

it("вкладка «Уязвимости»: реестр с V и сроком, «как посчитано», выбор H специалистом", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  const calls = fakeApi({
    "GET /me": () => json(EXP),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json(OBJ),
    "GET /objects/o1/hosts": () => json([]),
    "GET /objects/o1/vulns": () => json(REGISTER),
    "GET /refs/vuln-criticality/fstec-2025": () => json(METHODOLOGY),
    "GET /object-vulns/v1": () => json(detail(CURRENT, [ASSESSMENT])),
    "GET /object-vulns/v2": () => json(detail(INCOMPLETE, [])),
    "PATCH /object-vulns/v2": () =>
      json(detail({ ...INCOMPLETE, state: "current", state_title: "Оценка актуальна", missing: [] }, [ASSESSMENT])),
  });
  renderAt("/objects/o1?tab=vulns");

  expect(await screen.findByText(/прошёл рекомендуемый срок устранения/)).toBeInTheDocument();
  const first = screen.getByText("BDU:2025-03219").closest("tr")!;
  expect(within(first).getByText("Критический")).toHaveClass("pill-sev-critical");
  expect(within(first).getByText("8,47")).toBeInTheDocument();
  expect(within(first).getByText("просрочен")).toBeInTheDocument();
  const second = screen.getByText("BDU:2024-04835").closest("tr")!;
  expect(within(second).getByText("нужно: H")).toBeInTheDocument();

  // Карточка с трассировкой: откуда взято каждое значение.
  fireEvent.click(within(first).getByRole("button", { name: "BDU:2025-03219" }));
  const drawer = await screen.findByRole("dialog", { name: "BDU:2025-03219" });
  expect(await within(drawer).findByText("Оценка №1 — как посчитано")).toBeInTheDocument();
  expect(within(drawer).getAllByText("Сервер: 4 из 5 (80 %) → L1")[0]).toBeInTheDocument();
  expect(within(drawer).getAllByText("Инвентаризация")[0]).toHaveClass("pill");
  fireEvent.click(within(drawer).getByRole("button", { name: "Закрыть" }));

  // Не хватает H — специалист выбирает последствия.
  fireEvent.click(within(second).getByRole("button", { name: "BDU:2024-04835" }));
  const d2 = await screen.findByRole("dialog", { name: "BDU:2024-04835" });
  expect(await within(d2).findByText(/Для расчёта не хватает данных/)).toBeInTheDocument();
  // E из БДУ нельзя снять — только добавить.
  expect(within(d2).getByRole("button", { name: /E2 ·/ })).toBeDisabled();
  fireEvent.click(within(d2).getByRole("button", { name: /H1 · Выполнение произвольного кода/ }));
  fireEvent.click(within(d2).getByRole("button", { name: "Сохранить и рассчитать" }));
  await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
  const body = calls.find((c) => c.method === "PATCH")?.body as Record<string, unknown>;
  expect(body).toMatchObject({ h: ["H1"], e: [], certified_szi: false, manual_hosts: [] });
  expect(body.cvss).toBeUndefined();
});
