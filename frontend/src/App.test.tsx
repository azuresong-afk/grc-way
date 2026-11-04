import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "./App";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}

describe("каркас приложения", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ status: "ok", db: "ok" }))),
    );
  });

  afterEach(() => vi.unstubAllGlobals());

  it("с корня ведёт на сводку и показывает состояние сервера", async () => {
    renderAt("/");
    expect(screen.getByRole("heading", { level: 1, name: "Сводка" })).toBeInTheDocument();
    expect(await screen.findByText("Сервер и база данных доступны.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Сводка" })).toHaveClass("active");
  });

  it("сообщает, если сервер недоступен", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 503 })));
    renderAt("/summary");
    expect(await screen.findByRole("alert")).toHaveTextContent("недоступен");
  });

  it("переключает тему и запоминает выбор", () => {
    renderAt("/summary");
    fireEvent.click(screen.getByRole("button", { name: "Светлая тема" }));
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(localStorage.getItem("platform.theme")).toBe("light");
    expect(screen.getByRole("button", { name: "Тёмная тема" })).toBeInTheDocument();
  });

  it("неизвестный адрес — страница «не найдена»", () => {
    renderAt("/nope");
    expect(screen.getByText("Страница не найдена")).toBeInTheDocument();
  });
});
