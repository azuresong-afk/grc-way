import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import { fakeApi, json } from "../test/fakeApi";

const ME = {
  id: "u2",
  username: "m",
  display_name: "Иванова А. А.",
  roles: ["methodologist"],
  permissions: ["view", "refs.verify"],
};

const PROFILE = {
  id: "fstec-117",
  title: "Приказ ФСТЭК России №117 (ГИС)",
  short: "ФСТЭК №117",
  document: "Требования о защите информации…",
  url: null,
  level_label: "Класс защищённости",
  levels: ["К1", "К2", "К3"],
  dynamic: null,
  imported_at: "2026-11-04T15:00:00Z",
  total: 2,
  unverified: 2,
  groups: [{ code: "ИАФ", title: "Идентификация и аутентификация", total: 2, unverified: 2 }],
};

const M1 = {
  profile_id: "fstec-117",
  id: "ИАФ.1",
  group_code: "ИАФ",
  title: "Идентификация пользователей",
  text: null,
  levels: ["К1", "К2", "К3"],
  checks: ["no_empty_passwords"],
  kind: "technical",
  source: { document: "ФСТЭК №117", note: "Импорт из профиля «Сканера»" },
  origin: "scanner",
  verified: false,
  verified_by_name: null,
  verified_at: null,
  revision: 3,
  updated_at: "2026-11-04T15:00:00Z",
};
const M2 = { ...M1, id: "ИАФ.2", title: "Идентификация устройств", levels: [], checks: [], kind: "organizational" };

it("справочник: меры с отметкой «требует сверки», шторка и сверка", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  const calls = fakeApi({
    "GET /me": () => json(ME),
    "GET /projects": () => json([]),
    "GET /refs/profiles": () => json([PROFILE]),
    "GET /refs/measures": () => json([M1, M2], 200, { "X-Total-Count": "2" }),
    "GET /refs/measures/fstec-117/ИАФ.1": () =>
      json({
        ...M1,
        check_details: [{ id: "no_empty_passwords", title: "Нет пустых паролей", platform: "linux", remediation: null }],
        revisions: [],
      }),
    "POST /refs/measures/fstec-117/ИАФ.1/verify": () =>
      json({ ...M1, verified: true, verified_by_name: "Иванова А. А.", verified_at: "2026-11-04T16:00:00Z" }),
  });
  render(
    <MemoryRouter initialEntries={["/refs"]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );

  expect(await screen.findByText("Идентификация устройств")).toBeInTheDocument();
  expect(within(screen.getByRole("table")).getAllByText("Требует сверки")).toHaveLength(2);
  expect(screen.getByText("вне базового набора")).toBeInTheDocument();

  fireEvent.click(screen.getByText("Идентификация пользователей"));
  const drawer = await screen.findByRole("dialog");
  expect(await within(drawer).findByText(/Нет пустых паролей/)).toBeInTheDocument();
  expect(within(drawer).getByText(/Текст требования не загружен/)).toBeInTheDocument();
  // У методиста нет права править справочник.
  expect(within(drawer).queryByRole("button", { name: "Изменить" })).not.toBeInTheDocument();

  fireEvent.click(within(drawer).getByRole("button", { name: "Сверено" }));
  await waitFor(() => expect(within(drawer).getByText(/Сверил\(а\) Иванова А\. А\./)).toBeInTheDocument());
  expect(calls.find((c) => c.method === "POST")?.body).toEqual({ revision: 3 });
});
