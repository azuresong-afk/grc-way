import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import { fakeApi, json } from "../test/fakeApi";
import type { Diff, DiffItem } from "./ScannerSyncPage";

const ADMIN = {
  id: "u1",
  username: "admin",
  display_name: "Админ",
  roles: ["admin"],
  permissions: ["users.manage", "refs.manage", "integrations.manage", "audit.view"],
};

const SOURCE = {
  mode: "live",
  source: "http://scanner:8000",
  last_synced_at: null,
  pending_diff_id: null,
};

const base = {
  profile_id: "fstec-117",
  group_code: "ИАФ",
  origin: "scanner",
  revision: 1,
  verified: false,
  conflict: false,
  default: true,
};

const ITEMS: DiffItem[] = [
  {
    ...base,
    key: "fstec-117:ИАФ.1",
    measure_id: "ИАФ.1",
    action: "update",
    title: "Идентификация пользователей",
    fields: [{ field: "levels", before: ["К1", "К2", "К3"], after: ["К1"] }],
    verified: true,
  },
  {
    ...base,
    key: "fstec-117:ИАФ.2",
    measure_id: "ИАФ.2",
    action: "update",
    title: "Своя формулировка",
    origin: "local",
    conflict: true,
    default: false,
    fields: [{ field: "title", before: "Своя формулировка", after: "Из «Сканера»" }],
  },
  {
    ...base,
    key: "fstec-117:ИАФ.9",
    measure_id: "ИАФ.9",
    action: "add",
    title: "Новая мера",
    origin: null,
    revision: null,
    fields: [{ field: "levels", before: null, after: ["К1"] }],
  },
  {
    ...base,
    key: "fstec-117:ИАФ.4",
    measure_id: "ИАФ.4",
    action: "remove",
    title: "Удаляемая мера",
    fields: [],
  },
];

const DIFF: Diff = {
  id: "d1",
  created_at: "2026-11-04T19:00:00Z",
  created_by_name: "Админ",
  mode: "live",
  source: "http://scanner:8000",
  status: "pending",
  applied_at: null,
  applied_by_name: null,
  applied: null,
  summary: {
    add: 1,
    update: 2,
    remove: 1,
    unchanged: 358,
    conflict: 1,
    verified_affected: 1,
    profiles_new: 0,
    profiles_changed: 0,
    profiles_missing: 0,
    checks_added: 0,
    checks_changed: 0,
    has_changes: true,
  },
  profiles: [
    {
      id: "fstec-117",
      title: "ФСТЭК №117",
      status: "changed",
      fields: [],
      groups: [],
      counts: { add: 1, update: 2, remove: 1, unchanged: 111, conflict: 1 },
      total: 115,
    },
  ],
  items: ITEMS,
  checks: { added: [], changed: [] },
};

it("экран разницы: сравнение, конфликт по умолчанию не выбран, применение выбранного", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  const calls = fakeApi({
    "GET /me": () => json(ADMIN),
    "GET /projects": () => json([]),
    "GET /refs/scanner-source": () => json(SOURCE),
    "GET /refs/scanner-diffs": () => json([]),
    "POST /refs/profiles/scanner-diff": () => json(DIFF, 201),
    "GET /refs/scanner-diffs/d1": () => json(DIFF),
    "POST /refs/profiles/scanner-apply": () =>
      json({
        ...DIFF,
        status: "applied",
        applied_at: "2026-11-04T19:05:00Z",
        applied_by_name: "Админ",
        applied: { added: 1, updated: 1, removed: 0, skipped: 2 },
      }),
  });
  render(
    <MemoryRouter initialEntries={["/refs/scanner"]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );

  expect(await screen.findByText("Сравнений ещё не было")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Сравнить со «Сканером»" }));

  const table = await screen.findByRole("table");
  expect(within(table).getByText("Из «Сканера»")).toBeInTheDocument();
  expect(within(table).getByText("Правка в интерфейсе")).toBeInTheDocument();
  expect(within(table).getByText("Сверка снимется")).toBeInTheDocument();
  expect(screen.getByText(/Затронуто сверенных методистом мер: 1/)).toBeInTheDocument();
  // Убранный уровень зачёркнут.
  expect(
    within(table)
      .getAllByTitle("Убрано")
      .map((e) => e.textContent),
  ).toEqual(["К2", "К3"]);

  const conflict = screen.getByRole("checkbox", { name: "Применить ИАФ.2" });
  expect(conflict).not.toBeChecked();
  expect(screen.getByRole("checkbox", { name: "Применить ИАФ.1" })).toBeChecked();
  // Не удаляем ИАФ.4.
  fireEvent.click(screen.getByRole("checkbox", { name: "Применить ИАФ.4" }));
  expect(screen.getByText(/Выбрано 2 из 4/)).toBeInTheDocument();

  // Фильтр «Удалено».
  const chips = screen.getByRole("group", { name: "Фильтр изменений" });
  fireEvent.click(within(chips).getByRole("button", { name: /^Удалено/ }));
  expect(within(screen.getByRole("table")).queryByText("Новая мера")).not.toBeInTheDocument();
  fireEvent.click(within(chips).getByRole("button", { name: /^Все/ }));

  fireEvent.click(screen.getByRole("button", { name: "Применить…" }));
  const dialog = await screen.findByRole("dialog");
  fireEvent.click(within(dialog).getByRole("button", { name: "Применить" }));
  await waitFor(() => expect(screen.getByText(/добавлено 1, изменено 1/)).toBeInTheDocument());
  const body = calls.find((c) => c.path === "/refs/profiles/scanner-apply")?.body as {
    diff_id: string;
    selected: string[];
  };
  expect(body.diff_id).toBe("d1");
  expect(body.selected.sort()).toEqual(["fstec-117:ИАФ.1", "fstec-117:ИАФ.9"]);
  expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
});

it("экран разницы: методист видит, но не сравнивает и не применяет", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  fakeApi({
    "GET /me": () =>
      json({ ...ADMIN, roles: ["methodologist"], permissions: ["view", "refs.verify"] }),
    "GET /projects": () => json([]),
    "GET /refs/scanner-source": () => json({ ...SOURCE, pending_diff_id: "d1" }),
    "GET /refs/scanner-diffs": () => json([DIFF]),
    "GET /refs/scanner-diffs/d1": () => json(DIFF),
  });
  render(
    <MemoryRouter initialEntries={["/refs/scanner"]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
  expect(await screen.findByText("Удаляемая мера")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Сравнить со «Сканером»" })).not.toBeInTheDocument();
  expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Применить…" })).not.toBeInTheDocument();
  expect(screen.getByText("Ждёт применения")).toBeInTheDocument();
});
