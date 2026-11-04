import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "./App";
import { AuthProvider } from "./lib/auth";
import { TOKEN_KEY } from "./lib/api";
import { fakeApi, json } from "./test/fakeApi";

const ADMIN = {
  id: "u1",
  username: "admin",
  display_name: "Петров П. П.",
  roles: ["admin"],
  permissions: ["audit.view", "integrations.manage", "refs.manage", "users.manage"],
};
const METHODOLOGIST = {
  ...ADMIN,
  id: "u2",
  display_name: "Иванова А. А.",
  roles: ["methodologist", "approve"],
  permissions: ["view", "objects.edit", "approve"],
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

const health = () => json({ status: "ok", db: "ok" });

describe("вход и каркас", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
  afterEach(() => vi.unstubAllGlobals());

  it("без входа ведёт на форму входа, после входа — на сводку", async () => {
    const calls = fakeApi({
      "POST /auth/token": () => json({ access_token: "tok", token_type: "bearer", expires_in: 60 }),
      "GET /me": () => json(METHODOLOGIST),
      "GET /health/ready": health,
    });
    renderAt("/summary");
    expect(screen.getByRole("heading", { name: "Вход" })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Имя пользователя"), { target: { value: "ivanova" } });
    fireEvent.change(screen.getByLabelText("Пароль"), { target: { value: "long-enough-pass" } });
    fireEvent.click(screen.getByRole("button", { name: "Войти" }));

    expect(await screen.findByRole("heading", { level: 1, name: "Сводка" })).toBeInTheDocument();
    expect(sessionStorage.getItem(TOKEN_KEY)).toBe("tok");
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
    expect(calls.find((c) => c.path === "/me")?.auth).toBe("Bearer tok");
    expect(screen.getByText("Иванова А. А.")).toBeInTheDocument();
    expect(screen.getByText("Методист, Утверждающий")).toBeInTheDocument();
    // Рабочей роли меню администрирования не показывается.
    expect(screen.queryByText("Администрирование")).not.toBeInTheDocument();
  });

  it("показывает ошибку входа от сервера", async () => {
    fakeApi({ "POST /auth/token": () => json({ detail: "Неверное имя или пароль" }, 401) });
    renderAt("/login");
    fireEvent.change(screen.getByLabelText("Имя пользователя"), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText("Пароль"), { target: { value: "y" } });
    fireEvent.click(screen.getByRole("button", { name: "Войти" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Неверное имя или пароль");
  });

  it("истёкший токен — снова форма входа", async () => {
    sessionStorage.setItem(TOKEN_KEY, "old");
    fakeApi({ "GET /me": () => json({ detail: "Требуется вход" }, 401) });
    renderAt("/summary");
    expect(await screen.findByRole("heading", { name: "Вход" })).toBeInTheDocument();
    expect(sessionStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it("администратор видит раздел администрирования и журнал", async () => {
    sessionStorage.setItem(TOKEN_KEY, "tok");
    fakeApi({
      "GET /me": () => json(ADMIN),
      "GET /audit": () =>
        json(
          [
            {
              id: 1,
              at: "2026-11-04T13:54:00Z",
              user_name: "Петров П. П.",
              action: "auth.login",
              entity: null,
              entity_id: null,
              result: "ok",
              ip: "10.0.0.1",
              details: {},
            },
          ],
          200,
          { "X-Total-Count": "1" },
        ),
    });
    renderAt("/admin/audit");
    expect(await screen.findByRole("heading", { level: 1, name: "Журнал аудита" })).toBeInTheDocument();
    const row = (await screen.findByText("10.0.0.1")).closest("tr")!;
    expect(within(row).getByText("Вход")).toBeInTheDocument();
    expect(within(row).getByText("Успешно")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Пользователи и роли" })).toBeInTheDocument();
  });

  it("рабочей роли раздел пользователей закрыт", async () => {
    sessionStorage.setItem(TOKEN_KEY, "tok");
    fakeApi({ "GET /me": () => json(METHODOLOGIST) });
    renderAt("/admin/users");
    expect(await screen.findByRole("alert")).toHaveTextContent("Недостаточно прав");
  });

  it("администратор создаёт пользователя", async () => {
    sessionStorage.setItem(TOKEN_KEY, "tok");
    const calls = fakeApi({
      "GET /me": () => json(ADMIN),
      "GET /users": () => json([], 200, { "X-Total-Count": "0" }),
      "POST /users": () => json({}, 201),
    });
    renderAt("/admin/users");
    fireEvent.click(await screen.findByRole("button", { name: "Добавить пользователя" }));
    const dialog = screen.getByRole("dialog", { name: "Новый пользователь" });
    fireEvent.change(within(dialog).getByLabelText(/^Имя пользователя/), {
      target: { value: "sidorov" },
    });
    fireEvent.change(within(dialog).getByLabelText("ФИО"), { target: { value: "Сидоров С. С." } });
    fireEvent.change(within(dialog).getByLabelText(/^Пароль/), {
      target: { value: "long-enough-pass" },
    });
    fireEvent.click(within(dialog).getByLabelText(/Эксперт/));
    fireEvent.click(within(dialog).getByRole("button", { name: "Создать" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/users")).toBe(true));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({
      username: "sidorov",
      display_name: "Сидоров С. С.",
      password: "long-enough-pass",
      roles: ["assessor"],
    });
  });

  it("переключает тему и запоминает выбор", async () => {
    sessionStorage.setItem(TOKEN_KEY, "tok");
    fakeApi({ "GET /me": () => json(METHODOLOGIST), "GET /health/ready": health });
    renderAt("/summary");
    fireEvent.click(await screen.findByRole("button", { name: "Светлая тема" }));
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(localStorage.getItem("platform.theme")).toBe("light");
  });

  it("не уводит после входа на внешний адрес", async () => {
    fakeApi({
      "POST /auth/token": () => json({ access_token: "tok", token_type: "bearer", expires_in: 60 }),
      "GET /me": () => json(METHODOLOGIST),
      "GET /health/ready": health,
    });
    renderAt("/login?next=//evil.example");
    fireEvent.change(screen.getByLabelText("Имя пользователя"), { target: { value: "a" } });
    fireEvent.change(screen.getByLabelText("Пароль"), { target: { value: "b" } });
    fireEvent.click(screen.getByRole("button", { name: "Войти" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Сводка" })).toBeInTheDocument();
  });
});
