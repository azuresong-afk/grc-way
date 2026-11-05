import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import type { NcDetail, NcItem, Plan } from "../lib/nonconformities";
import type { ObjectFull } from "../lib/objects";
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

const item = (over: Partial<NcItem>): NcItem => ({
  id: "n1",
  kind: "vuln",
  ref: "BDU:2024-04835",
  title: "OpenSSH: состояние гонки",
  object_measure_id: null,
  object_vuln_id: "v1",
  source_status: "current",
  source_status_title: "Оценка актуальна",
  measure_method: null,
  hosts: ["10.10.1.10", "10.10.1.11"],
  details: null,
  v: "8.47",
  level: "critical",
  level_title: "Критический",
  assessed_at: "2026-11-01T10:00:00Z",
  deadline_at: "2026-11-02T10:00:00Z",
  certified_szi: false,
  priority: null,
  due_date: null,
  action: null,
  default_action: "Устранить уязвимость (обновление или компенсирующие меры)",
  responsible: null,
  comment: null,
  method: null,
  update_origin: null,
  update_tested: null,
  compensating: [],
  opened_at: "2026-11-01T10:00:00Z",
  closed_at: null,
  close_reason: null,
  state: "open",
  state_title: "Не отправлено",
  overdue: true,
  send_blocker: null,
  resend: false,
  warnings: [],
  vm_ticket_id: null,
  vm_status: null,
  vm_status_title: null,
  vm_status_at: null,
  vm_verified_result: null,
  vm_verified_at: null,
  vm_verified_run_id: null,
  ticket_url: null,
  sent_at: null,
  sent_by_name: null,
  updated_at: "2026-11-01T10:00:00Z",
  updated_by_name: null,
  ...over,
});

const VULN = item({});
const MEASURE = item({
  id: "n2",
  kind: "measure",
  ref: "АНЗ.1",
  title: "Выявление, анализ уязвимостей",
  object_measure_id: "m1",
  object_vuln_id: null,
  source_status: "not_implemented",
  source_status_title: "Не реализована",
  measure_method: "manual",
  v: null,
  level: null,
  level_title: null,
  deadline_at: null,
  overdue: false,
  priority: "high",
  send_blocker: "Организационная мера устраняется документами, а не заявкой",
});

const PLAN: Plan = {
  object_id: "o1",
  vm: { mode: "fixture", source: "встроенная заглушка", project_id: "vm-1", events: true },
  compensating_measures: [
    { code: "CM1", title: "Изменение конфигурации уязвимых компонентов" },
    { code: "CM2", title: "Ограничение использования уязвимых средств" },
  ],
  counts: { total: 2, measures: 1, vulns: 1, open: 2, in_vm: 0, verified: 0, decision: 0, overdue: 1, critical: 1, high: 0 },
  items: [MEASURE, VULN],
};

const detail = (i: NcItem): NcDetail => ({ ...i, history: [{ at: i.opened_at, kind: "opened", text: "Уязвимость в реестре объекта", actor_name: null }] });

function renderAt(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

it("вкладка «Несоответствия»: просрочка, способ устранения, отправка в «Устранение»", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  const sent = item({ state: "in_work", state_title: "В работе", vm_ticket_id: "512", vm_status: "new", vm_status_title: "Новая", method: "compensating", compensating: ["CM2"] });
  const calls = fakeApi({
    "GET /me": () => json(EXP),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json(OBJ),
    "GET /objects/o1/hosts": () => json([]),
    "GET /objects/o1/nonconformities": () => json(PLAN),
    "GET /nonconformities/n1": () => json(detail(VULN)),
    "PATCH /nonconformities/n1": () => json(detail({ ...VULN, method: "compensating", compensating: ["CM2"] })),
    "POST /nonconformities/n1/send": () => json(detail(sent)),
  });
  renderAt("/objects/o1?tab=plan");

  expect(await screen.findByText(/Просрочено пунктов плана: 1/)).toBeInTheDocument();
  const vulnRow = screen.getByText("BDU:2024-04835").closest("tr")!;
  expect(within(vulnRow).getByText("Критический")).toHaveClass("pill-sev-critical");
  expect(within(vulnRow).getByText("просрочен")).toBeInTheDocument();
  // Организационную меру выбрать для отправки нельзя.
  const measureRow = screen.getByText("АНЗ.1").closest("tr")!;
  expect(within(measureRow).getByRole("checkbox")).toBeDisabled();

  fireEvent.click(within(vulnRow).getByText("BDU:2024-04835"));
  const drawer = await screen.findByRole("dialog");
  fireEvent.click(within(drawer).getByRole("radio", { name: "Компенсирующие меры" }));
  fireEvent.click(within(drawer).getByRole("checkbox", { name: /CM2/ }));
  fireEvent.click(within(drawer).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
  const patch = calls.find((c) => c.method === "PATCH")!;
  expect(patch.body).toMatchObject({ method: "compensating", compensating: ["CM2"], update_origin: null });

  fireEvent.click(within(drawer).getByRole("button", { name: /Отправить в «Устранение»/ }));
  expect(await within(drawer).findByText(/№512/)).toBeInTheDocument();
  expect(calls.some((c) => c.method === "POST" && c.path === "/nonconformities/n1/send")).toBe(true);
});
