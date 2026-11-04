import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import type { ObjectFull } from "../lib/objects";
import type { Cert, ObjectSzi, RegistryStatus, SziImport, SziList } from "../lib/szi";
import { fakeApi, json } from "../test/fakeApi";

const METH = {
  id: "u2",
  username: "meth",
  display_name: "Иванова А. А.",
  roles: ["methodologist"],
  permissions: ["view", "objects.edit", "projects.manage"],
};
const ADMIN = { id: "u1", username: "root", display_name: "Администратор", roles: ["admin"], permissions: ["refs.manage"] };

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
};

const base: Omit<ObjectSzi, "id" | "name" | "state" | "state_title" | "level"> = {
  object_id: "o1",
  kind: "fw",
  kind_title: "Межсетевой экран",
  vendor: null,
  version: null,
  cert_number: "9901",
  cert_valid_to: null,
  trust_level: 4,
  protection_class: null,
  placement: null,
  measure_ids: ["МСЭ.3"],
  measures: [{ measure_id: "МСЭ.3", title: "Контроль сетевого доступа", state: "in_set" }],
  comment: null,
  valid_to: "2028-10-04",
  valid_to_source: "registry",
  days_left: 700,
  registry_match: "found",
  effective_trust_level: 4,
  support_ended: false,
  notes: [],
  registry: null,
  created_at: "2026-11-04T10:00:00Z",
  created_by_name: "Иванова А. А.",
  updated_at: "2026-11-04T10:00:00Z",
  updated_by_name: "Иванова А. А.",
};

const LIST: SziList = {
  items: [
    {
      ...base,
      id: "z2",
      name: "Пример-НСД",
      kind: "nsd",
      kind_title: "Средство защиты от НСД",
      cert_number: "9903",
      valid_to: "2026-10-05",
      days_left: -30,
      state: "expired",
      state_title: "Срок истёк",
      level: "bad",
      measures: [{ measure_id: "ИАФ.1", title: null, state: "missing" }],
    },
    { ...base, id: "z1", name: "Пример-МЭ", state: "valid", state_title: "Действует", level: "ok" },
  ],
  counts: { total: 2, bad: 1, expiring: 0, check: 0, uncertified: 0 },
  expiry_days: 90,
  registry_version: "2026-10-05",
  registry_loaded: true,
  kinds: { fw: "Межсетевой экран", nsd: "Средство защиты от НСД", other: "Другое" },
  states: {} as SziList["states"],
};

const MEASURES = [
  { id: "m1", measure_id: "МСЭ.3", title: "Контроль сетевого доступа", group_code: "МСЭ" },
  { id: "m2", measure_id: "АВЗ.1", title: "Антивирусная защита устройств", group_code: "АВЗ" },
];

const CERT: Cert = {
  cert_number: "9902",
  name: "Образец: средство антивирусной защиты «Пример-АВЗ»",
  registered_on: "2022-07-17",
  valid_to: "2026-12-19",
  valid_to_raw: null,
  trust_level: 4,
  profiles: ["ИТ.САВЗ.Б4.ПЗ"],
  cert_status: "active",
  support_until: null,
  applicant: "Образец: ООО «Пример»",
  changed_version: "2026-10-05",
  withdrawn_at: null,
  requirements: "Требования доверия(4)",
  scheme: "серия",
  lab: null,
  cert_body: "ФСТЭК России",
  applicant_details: null,
  support_raw: null,
  note: null,
  first_version: "2026-10-05",
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

it("вкладка СЗИ: предупреждение о недействительном сертификате, добавление с поиском в реестре", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  const calls = fakeApi({
    "GET /me": () => json(METH),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json(OBJ),
    "GET /objects/o1/hosts": () => json([]),
    "GET /objects/o1/szi": () => json(LIST),
    "GET /objects/o1/measures": () => json(MEASURES),
    "GET /szi-registry/9902": () => json(CERT),
    "POST /objects/o1/szi": () => json({ ...base, id: "z3", name: CERT.name }, 201),
  });
  renderAt("/objects/o1?tab=szi");

  expect(await screen.findByText(/У 1 СЗИ сертификат недействителен/)).toBeInTheDocument();
  const row = screen.getByText("Пример-НСД").closest("tr")!;
  expect(within(row).getByText("Срок истёк")).toHaveClass("pill-danger");
  expect(within(row).getByText("истёк 30 дн. назад")).toBeInTheDocument();
  expect(within(row).getByText("ИАФ.1")).toHaveClass("tag-muted");
  // Сначала худшие — порядок как пришёл с сервера.
  const rows = screen.getAllByRole("row").slice(1);
  expect(within(rows[0]!).getByText("Пример-НСД")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /Добавить СЗИ/ }));
  const dialog = await screen.findByRole("dialog", { name: "Добавить СЗИ" });
  fireEvent.change(within(dialog).getByPlaceholderText("например, 4512"), { target: { value: "9902" } });
  fireEvent.click(within(dialog).getByRole("button", { name: /В реестре/ }));
  expect(await within(dialog).findByText(/Срок и уровень доверия берутся из реестра/)).toBeInTheDocument();
  expect(within(dialog).getByLabelText("Наименование")).toHaveValue(CERT.name);
  fireEvent.click(within(dialog).getByRole("checkbox", { name: /АВЗ.1/ }));
  fireEvent.click(within(dialog).getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
  const body = calls.find((c) => c.method === "POST")?.body as Record<string, unknown>;
  expect(body).toMatchObject({ name: CERT.name, cert_number: "9902", trust_level: 4, measure_ids: ["АВЗ.1"] });
});

const STATUS: RegistryStatus = {
  version: "2026-10-05",
  version_source: "title",
  applied_at: "2026-11-04T10:00:00Z",
  applied_by_name: "Администратор",
  active: 6,
  withdrawn: 0,
  expired: 1,
  expiring: 1,
  pending_id: "i2",
  expiry_days: 90,
};

const IMPORT: SziImport = {
  id: "i2",
  file_name: "reestr-szi.csv",
  file_size: 2048,
  file_ext: "csv",
  export_version: "2026-11-03",
  version_source: "title",
  version_source_title: "дата в заголовке файла",
  status: "pending",
  summary: {
    in_file: 6,
    add: 1,
    update: 1,
    restore: 0,
    withdraw: 1,
    unchanged: 4,
    validity: 1,
    has_changes: true,
    items_shown: 3,
    items_total: 3,
    title: null,
  },
  warnings: [],
  created_at: "2026-11-04T11:00:00Z",
  created_by_name: "Администратор",
  applied_at: null,
  applied_by_name: null,
  applied: null,
  items: [
    { key: "9902", change: "update", title: "Пример-АВЗ", fields: { valid_to: ["2026-12-19", "2029-12-18"] }, validity: true },
    { key: "9903", change: "withdraw", title: "Пример-НСД" },
    { key: "9907", change: "add", title: "Пример-СКН", valid_to: "2031-10-09", trust_level: 4 },
  ],
  field_titles: { valid_to: "Срок действия сертификата" },
};

it("реестр СЗИ: сравнение показывает смену срока и применяется", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  const calls = fakeApi({
    "GET /me": () => json(ADMIN),
    "GET /projects": () => json([]),
    "GET /szi-registry/status": () => json(STATUS),
    "GET /szi-registry/imports": () => json([IMPORT]),
    "GET /szi-registry/imports/i2": () => json(IMPORT),
    "POST /szi-registry/imports/i2/apply": () =>
      json({
        ...IMPORT,
        status: "applied",
        applied_at: "2026-11-04T12:00:00Z",
        applied_by_name: "Администратор",
        applied: { added: 1, updated: 1, restored: 0, withdrawn: 1, validity: 1 },
      }),
  });
  renderAt("/refs/szi?tab=imports&import=i2");

  const row = (await screen.findByText("Пример-АВЗ")).closest("tr")!;
  expect(within(row).getByText("19.12.2026")).toBeInTheDocument();
  expect(within(row).getByText("18.12.2029")).toBeInTheDocument();
  expect(within(row).getByText("Срок или состояние")).toBeInTheDocument();
  expect(screen.getByText(/СЗИ объектов с этим номером получат предупреждение/)).toBeInTheDocument();
  expect(screen.getByText(/Требует сверки/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Применить реестр" }));
  await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
  expect(await screen.findByText(/со сменой срока или состояния 1/)).toBeInTheDocument();
});
