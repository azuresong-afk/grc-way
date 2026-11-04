import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import type { ThreatItem, ThreatKind } from "../lib/threats";
import { fakeApi, json } from "../test/fakeApi";

const ME = {
  id: "u2",
  username: "m",
  display_name: "Иванова А. А.",
  roles: ["methodologist", "admin"],
  permissions: ["view", "refs.verify", "refs.manage"],
};

const DOC = { document: "Методика оценки угроз безопасности информации (утв. ФСТЭК России 05.02.2021)" };

function item(code: string, kind: ThreatKind, title: string, extra: Partial<ThreatItem> = {}): ThreatItem {
  return {
    code,
    kind,
    parent_code: null,
    position: 0,
    title,
    description: null,
    attrs: {},
    source: { ...DOC, appendix: kind === "tactic" ? "11" : null },
    origin: "stub",
    revision: 1,
    verified: false,
    verified_by_name: null,
    verified_at: null,
    updated_at: "2026-11-04T15:00:00Z",
    ...extra,
  };
}

const ITEMS = [
  item("У1", "consequence_type", "Ущерб физическому лицу"),
  item("У1.1", "consequence", "Угроза жизни или здоровью", { parent_code: "У1", position: 1 }),
  item("Н1", "capability", "Нарушитель, обладающий базовыми возможностями"),
  item("НВ4", "intruder", "Отдельные физические лица (хакеры)", { attrs: { capability: "Н1", category: "внешний" } }),
  item("Т1", "tactic", "Сбор информации о системах и сетях"),
];

function listing(items: ThreatItem[]) {
  const kinds = Object.fromEntries(
    ["consequence_type", "consequence", "capability", "intruder", "tactic", "technique"].map((k) => [
      k,
      {
        total: items.filter((i) => i.kind === k).length,
        unverified: items.filter((i) => i.kind === k && !i.verified).length,
      },
    ]),
  );
  return { document: DOC, total: items.length, unverified: items.filter((i) => !i.verified).length, kinds, items };
}

function renderAt(path: string) {
  render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

it("методика: последствия по видам, нарушители, сверка записи", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  let items = ITEMS;
  const calls = fakeApi({
    "GET /me": () => json(ME),
    "GET /projects": () => json([]),
    "GET /refs/threats": () => json(listing(items)),
    "GET /refs/threats/У1.1": () => json({ ...items[1], revisions: [] }),
    "POST /refs/threats/У1.1/verify": () => {
      items = items.map((i) =>
        i.code === "У1.1" ? { ...i, verified: true, verified_by_name: "Иванова А. А.", verified_at: "2026-11-04T16:00:00Z" } : i,
      );
      return json(items[1]);
    },
  });
  renderAt("/refs/threats");

  expect(await screen.findByText("Угроза жизни или здоровью")).toBeInTheDocument();
  expect(screen.getByText(/Не сверено методистом: 5 из 5/)).toBeInTheDocument();

  fireEvent.click(screen.getByText("Угроза жизни или здоровью"));
  const drawer = await screen.findByRole("dialog");
  expect(within(drawer).getByText("Заглушка")).toBeInTheDocument();
  fireEvent.click(within(drawer).getByRole("button", { name: /Сверено/ }));
  await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/refs/threats/У1.1/verify")).toBe(true));
  expect(calls.find((c) => c.path === "/refs/threats/У1.1/verify")?.body).toEqual({ revision: 1 });
  await waitFor(() => expect(screen.getByText(/Не сверено методистом: 4 из 5/)).toBeInTheDocument());
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Закрыть" }));

  fireEvent.click(screen.getByRole("tab", { name: /Нарушители/ }));
  const row = (await screen.findByText("Отдельные физические лица (хакеры)")).closest("tr")!;
  expect(within(row).getByText("Н1")).toBeInTheDocument();
  expect(within(row).getByText("внешний")).toBeInTheDocument();
});

it("методика: тактики без техник — пояснение и добавление техники", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  let items = ITEMS;
  const calls = fakeApi({
    "GET /me": () => json(ME),
    "GET /projects": () => json([]),
    "GET /refs/threats": () => json(listing(items)),
    "GET /refs/threats/Т1": () => json({ ...items[4], revisions: [] }),
    "POST /refs/threats": (init) => {
      const body = JSON.parse(String(init?.body));
      const created = item(body.code, "technique", body.title, { parent_code: "Т1", origin: "local", position: 1 });
      items = [...items, created];
      return json({ ...created, revisions: [] }, 201);
    },
    "GET /refs/threats/Т1.1": () => json({ ...items[5], revisions: [] }),
  });
  renderAt("/refs/threats?tab=tactics");

  expect(await screen.findByText(/Техники приложения 11 не заполнены/)).toBeInTheDocument();
  fireEvent.click(screen.getByText("Сбор информации о системах и сетях"));
  const drawer = await screen.findByRole("dialog");
  fireEvent.click(within(drawer).getByRole("button", { name: /Добавить технику/ }));

  const modal = await screen.findByRole("dialog", { name: /Техника · Т1/ });
  expect(within(modal).getByLabelText("Код")).toHaveValue("Т1.1");
  fireEvent.change(within(modal).getByLabelText(/Наименование/), {
    target: { value: "Сбор информации из публичных источников" },
  });
  fireEvent.change(within(modal).getByLabelText(/Основание правки/), { target: { value: "по тексту" } });
  fireEvent.click(within(modal).getByRole("button", { name: "Сохранить" }));

  await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/refs/threats")).toBe(true));
  const sent = calls.find((c) => c.method === "POST" && c.path === "/refs/threats")?.body as Record<string, unknown>;
  expect(sent).toMatchObject({ kind: "technique", code: "Т1.1", parent_code: "Т1" });
  expect((sent.source as { appendix: string }).appendix).toBe("11");
  // Новая техника — в таблице под тактикой и открыта в карточке.
  const row = (await screen.findByRole("button", { name: "Т1.1" })).closest("tr")!;
  expect(row).toHaveClass("row-child");
  expect(within(row).getByText("Сбор информации из публичных источников")).toBeInTheDocument();
});
