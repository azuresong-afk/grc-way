import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import type { AssetsResponse, Host, ObjectFull, SyncResult } from "../lib/objects";
import { fakeApi, json } from "../test/fakeApi";
import { syncSummary } from "./ObjectPage";

const METH = {
  id: "u2",
  username: "meth",
  display_name: "Иванова А. А.",
  roles: ["methodologist"],
  permissions: ["view", "objects.edit", "projects.manage"],
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
  scanner_engagement_id: 7,
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
  host_count: 1,
  segment_count: 1,
  updated_at: "2026-11-04T10:00:00Z",
  purpose: "Учёт обращений",
  boundaries: null,
  interconnections: [{ system: "СМЭВ", direction: "both", channel: "VipNet" }],
  responsible: [{ name: "Петров П. П.", role: "Администратор безопасности" }],
  created_at: "2026-11-04T10:00:00Z",
  scanner_synced_at: null,
  scanner_engagement_id: 7,
  segments: [{ id: "s1", name: "ЛВС", description: null, scanner_group: null, host_count: 1 }],
};

const HOST: Host = {
  id: "h1",
  address: "10.0.0.5",
  hostname: "arm-5",
  role: "АРМ оператора",
  segment_id: "s1",
  os: null,
  os_family: null,
  source: "manual",
  scanner_asset_id: null,
  scanner_groups: [],
  criticality: null,
  owner: null,
  last_seen_at: null,
  scanner_missing: false,
  synced_at: null,
};

const asset = (address: string, group: string, extra: Partial<AssetsResponse["assets"][0]> = {}) => ({
  id: Number(address.split(".").pop()),
  address,
  hostname: `h-${address}`,
  os: "Astra Linux",
  os_family: "linux",
  criticality: "high",
  owner: null,
  groups: [group],
  last_seen_at: null,
  in_object: false,
  other_objects: [],
  ...extra,
});

const ASSETS: AssetsResponse = {
  engagement_id: 7,
  mode: "fixture",
  source: "фикстура",
  assets: [
    asset("10.0.0.5", "АРМ", { in_object: true }),
    asset("10.10.1.10", "Серверы"),
    asset("10.10.1.11", "Серверы", { other_objects: ["ИСПДн «Кадры»"] }),
    asset("10.20.0.1", "Бухгалтерия"),
  ],
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

it("карточка объекта: описание, состав и добавление хостов группой из «Сканера»", async () => {
  const result: SyncResult = {
    added: ["10.10.1.10", "10.10.1.11"],
    updated: [],
    linked: [],
    missing: [],
    segments_created: ["Серверы"],
    hosts: [HOST],
  };
  const calls = fakeApi({
    "GET /me": () => json(METH),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json(OBJ),
    "GET /objects/o1/hosts": () => json([HOST]),
    "GET /objects/o1/scanner/assets": () => json(ASSETS),
    "POST /objects/o1/hosts/sync-from-scanner": () => json(result),
  });
  renderAt("/objects/o1");

  expect(await screen.findByRole("heading", { name: "ГИС «Учёт»" })).toBeInTheDocument();
  expect(screen.getByText("Приказ ФСТЭК №117")).toBeInTheDocument();
  expect(screen.getByText("Петров П. П.")).toBeInTheDocument();
  expect(screen.getByText("СМЭВ")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("tab", { name: /Состав/ }));
  expect(await screen.findByText("10.0.0.5")).toBeInTheDocument();
  expect(screen.getByText("АРМ оператора")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /Из активов «Сканера»/ }));
  const dialog = await screen.findByRole("dialog");
  expect(await within(dialog).findByText(/также в: ИСПДн «Кадры»/)).toBeInTheDocument();
  // Хост уже в составе — отмечен и недоступен.
  const inObject = within(dialog).getByText(/уже в составе/).closest("label")!.querySelector("input")!;
  expect(inObject).toBeChecked();
  expect(inObject).toBeDisabled();

  fireEvent.click(within(dialog).getByRole("button", { name: /Серверы/ }));
  fireEvent.click(within(dialog).getByRole("button", { name: "Добавить 2" }));

  await waitFor(() =>
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({
      addresses: ["10.10.1.10", "10.10.1.11"],
      segments_from_groups: true,
    }),
  );
  expect(await screen.findByText(/добавлено 2 хоста; созданы сегменты: Серверы/)).toBeInTheDocument();
});

it("ручное добавление хоста отправляет весь состав и проверяет IP", async () => {
  const calls = fakeApi({
    "GET /me": () => json(METH),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json(OBJ),
    "GET /objects/o1/hosts": () => json([HOST]),
    "PUT /objects/o1/hosts": () => json([HOST, { ...HOST, id: "h2", address: "10.0.0.6" }]),
  });
  renderAt("/objects/o1?tab=composition");

  fireEvent.click(await screen.findByRole("button", { name: /Добавить вручную/ }));
  const dialog = await screen.findByRole("dialog");
  const ip = within(dialog).getByPlaceholderText("10.10.1.10");
  fireEvent.change(ip, { target: { value: "srv-06" } });
  fireEvent.click(within(dialog).getByRole("button", { name: "Добавить" }));
  expect(await within(dialog).findByText(/Укажите IP-адрес/)).toBeInTheDocument();

  fireEvent.change(ip, { target: { value: "10.0.0.6" } });
  fireEvent.change(within(dialog).getByPlaceholderText(/Сервер СУБД/), { target: { value: "СУБД" } });
  fireEvent.click(within(dialog).getByRole("button", { name: "Добавить" }));

  await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
  const put = calls.find((c) => c.method === "PUT")!;
  expect(put.body).toEqual({
    items: [
      { address: "10.0.0.5", hostname: "arm-5", role: "АРМ оператора", segment_id: "s1" },
      { address: "10.0.0.6", hostname: null, role: "СУБД", segment_id: null },
    ],
  });
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
});

it("наблюдатель видит состав без кнопок изменения", async () => {
  fakeApi({
    "GET /me": () =>
      json({ ...METH, roles: ["viewer"], permissions: ["view"], display_name: "Наблюдатель" }),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json(OBJ),
    "GET /objects/o1/hosts": () => json([HOST]),
  });
  renderAt("/objects/o1?tab=composition");
  expect(await screen.findByText("10.0.0.5")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Добавить вручную/ })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Изменить" })).not.toBeInTheDocument();
});

it("итог сверки со «Сканером» по-русски", () => {
  expect(
    syncSummary({
      added: [],
      updated: ["1.1.1.1"],
      linked: [],
      missing: ["2.2.2.2"],
      segments_created: [],
      hosts: [],
    }),
  ).toBe("Сверено со «Сканером»: обновлено 1 хост; нет в «Сканере»: 2.2.2.2.");
});
