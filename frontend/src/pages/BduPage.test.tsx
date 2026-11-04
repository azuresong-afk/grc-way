import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import type { BduStatus, Import, Vuln, VulnBrief } from "../lib/bdu";
import { fakeApi, json } from "../test/fakeApi";

const ADMIN = {
  id: "u1",
  username: "root",
  display_name: "Администратор",
  roles: ["admin"],
  permissions: ["refs.manage"],
};

function status(pending: string | null = null): BduStatus {
  const base = {
    version: "2026-10-01",
    version_source: "file",
    applied_at: "2026-11-04T10:00:00Z",
    applied_by_name: "Администратор",
    withdrawn: 0,
    criticality_last: null,
  };
  return {
    vulns: { ...base, kind: "vulns", title: "Уязвимости", file_name: "vullist.xlsx", active: 6, pending_id: pending, criticality_last: 0 },
    threats: { ...base, kind: "threats", title: "Угрозы (УБИ)", file_name: "thrlist.xlsx", active: 6, pending_id: null },
  };
}

const VULN: VulnBrief = {
  bdu_id: "BDU:2025-01611",
  title: "Уязвимость операционных систем FortiOS",
  vendor: "Fortinet Inc.",
  product: "FortiOS",
  cvss3_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
  cvss3_version: "3.1",
  cvss3_score: 8.8,
  cvss3_score_source: "bdu",
  exploit: "public",
  in_wild: "yes",
  e_level: "in_wild",
  status: "Подтверждена производителем",
  cve_ids: ["CVE-2024-55591"],
  changed_version: "2026-11-01",
  criticality_changed_at: "2026-11-04T11:00:00Z",
  withdrawn_at: null,
};

const DETAIL: Vuln = {
  ...VULN,
  description: "Уязвимость связана с некорректным присваиванием привилегий.",
  product_version: "от 7.0.0 до 7.0.16",
  sw_type: "Операционная система",
  platform: null,
  vuln_class: "Уязвимость кода",
  identified_on: "2025-02-11",
  published_on: null,
  severity: "Высокий уровень опасности (базовая оценка CVSS 3.1 составляет 8,8)",
  cvss_other: null,
  measures: null,
  exploit_raw: "Существует в открытом доступе",
  in_wild_raw: "Да",
  fix_info: null,
  links: null,
  cwe_ids: ["CWE-266"],
  other_ids: "CVE-2024-55591",
  other_info: null,
  exploit_method: null,
  fix_method: null,
  first_version: "2026-10-01",
  criticality_changes: { exploit: ["unknown", "public"], in_wild: ["unknown", "yes"] },
  criticality_changed_version: "2026-11-01",
};

const IMPORT: Import = {
  id: "imp2",
  kind: "vulns",
  file_name: "vullist.xlsx",
  file_size: 5_400,
  export_version: "2026-11-01",
  version_source: "file",
  version_source_title: "дата изменения файла (свойства документа)",
  status: "pending",
  summary: {
    kind: "vulns",
    in_file: 6,
    rows_in_file: 6,
    add: 1,
    update: 2,
    restore: 0,
    withdraw: 1,
    unchanged: 3,
    criticality: 1,
    skipped: 0,
    duplicates: 0,
    cvss_mismatch: 0,
    active_before: 6,
    has_changes: true,
    items_shown: 4,
    items_total: 4,
    header_row: 3,
    columns: {},
    title: null,
    crit_ids: ["BDU:2025-01611"],
  },
  warnings: [{ code: "older", text: "Выгрузка от 01.11.2026 старше загруженной" }],
  created_at: "2026-11-04T12:00:00Z",
  created_by_name: "Администратор",
  applied_at: null,
  applied_by_name: null,
  applied: null,
  items: [
    {
      key: "BDU:2025-01611",
      change: "update",
      title: "Уязвимость операционных систем FortiOS",
      fields: { exploit: ["unknown", "public"] },
      criticality: true,
    },
    { key: "BDU:2026-01377", change: "add", title: "Уязвимость СУБД", cvss3_score: 8.8, exploit: "unknown", in_wild: "unknown" },
    { key: "BDU:2015-07745", change: "withdraw", title: "Уязвимость веб-сервера" },
  ],
  field_titles: { exploit: "Наличие эксплойта" },
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

it("БДУ: список уязвимостей, фильтр и карточка с отметкой «пересчитать»", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  const calls = fakeApi({
    "GET /me": () => json(ADMIN),
    "GET /projects": () => json([]),
    "GET /bdu/status": () => json(status()),
    "GET /bdu/vulns": () => json([VULN], 200, { "X-Total-Count": "1" }),
    "GET /bdu/vulns/BDU:2025-01611": () => json(DETAIL),
  });
  renderAt("/refs/bdu");

  const row = (await screen.findByText("Уязвимость операционных систем FortiOS")).closest("tr")!;
  expect(within(row).getByText("Эксплуатируется")).toBeInTheDocument();
  expect(within(row).getByText("Пересчитать")).toBeInTheDocument();
  expect(screen.getAllByText(/выгрузка от 01.10.2026/, { selector: ".kpi-delta" })).toHaveLength(2);

  fireEvent.click(screen.getByRole("button", { name: "Изменились сведения для критичности" }));
  await waitFor(() =>
    expect(calls.some((c) => c.path === "/bdu/vulns" && c.method === "GET")).toBe(true),
  );

  fireEvent.click(within(row).getByRole("button", { name: "BDU:2025-01611" }));
  const drawer = await screen.findByRole("dialog");
  expect(await within(drawer).findByText(/оценки, сделанные раньше, нужно пересчитать/i)).toBeInTheDocument();
  expect(within(drawer).getByText("Эксплуатируется в реальных атаках")).toBeInTheDocument();
  expect(within(drawer).getAllByText("В открытом доступе").length).toBeGreaterThan(0);
});

it("БДУ: сравнение с предупреждением применяется только после подтверждения", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  const calls = fakeApi({
    "GET /me": () => json(ADMIN),
    "GET /projects": () => json([]),
    "GET /bdu/status": () => json(status("imp2")),
    "GET /bdu/imports": () => json([IMPORT]),
    "GET /bdu/imports/imp2": () => json(IMPORT),
    "POST /bdu/imports/imp2/apply": () =>
      json({
        ...IMPORT,
        status: "applied",
        applied_at: "2026-11-04T12:05:00Z",
        applied_by_name: "Администратор",
        applied: { added: 1, updated: 2, restored: 0, withdrawn: 1, criticality: 1 },
      }),
  });
  renderAt("/refs/bdu?tab=imports&import=imp2");

  expect(await screen.findByText(/старше загруженной/)).toBeInTheDocument();
  const critRow = screen.getByText("Пересчитать критичность").closest("tr")!;
  expect(within(critRow).getByText("BDU:2025-01611")).toBeInTheDocument();
  expect(screen.getByText(/Запись не удаляется/)).toBeInTheDocument();

  const apply = screen.getByRole("button", { name: "Применить выгрузку" });
  expect(apply).toBeDisabled();
  fireEvent.click(screen.getByLabelText(/Предупреждения прочитаны/));
  fireEvent.click(apply);
  await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
  expect(calls.find((c) => c.method === "POST")?.body).toEqual({ ack_warnings: true });
  expect(await screen.findByText(/требуют пересчёта критичности 1/)).toBeInTheDocument();
});
