import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("режим платформы (VITE_PLATFORM=1)", () => {
  const assign = vi.fn();

  beforeEach(() => {
    vi.resetModules();
    vi.stubEnv("VITE_PLATFORM", "1");
    sessionStorage.clear();
    localStorage.clear();
    assign.mockReset();
    vi.stubGlobal("location", { ...window.location, assign, pathname: "/grc/objects", search: "?project=p1" });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("строит межпродуктовые ссылки того же origin", async () => {
    const { productLink } = await import("./platform");
    expect(productLink("vm", "tickets/125", "p1")).toBe("/vm/tickets/125?project=p1");
    expect(productLink("scanner", "/runs/7")).toBe("/scanner/runs/7");
  });

  it("на 401 делает один общий refresh и повторяет запрос", async () => {
    sessionStorage.setItem("platform.token", "old");
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        calls.push(`${init?.method ?? "GET"} ${url} ${new Headers(init?.headers).get("Authorization") ?? ""}`);
        if (url === "/api/platform/auth/refresh") return json(200, { access_token: "new" });
        const auth = new Headers(init?.headers).get("Authorization");
        return auth === "Bearer new" ? json(200, { ok: true }) : json(401, { detail: "invalid_token" });
      }),
    );
    const { apiGet } = await import("./api");
    const [a, b] = await Promise.all([apiGet("/me"), apiGet("/projects")]);
    expect(a).toEqual({ ok: true });
    expect(b).toEqual({ ok: true });
    expect(calls.filter((c) => c.startsWith("POST /api/platform/auth/refresh"))).toHaveLength(1);
    expect(sessionStorage.getItem("platform.token")).toBe("new");
  });

  it("refresh не удался — на вход оболочки с next", async () => {
    sessionStorage.setItem("platform.token", "old");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => json(401, { detail: "invalid_token" })),
    );
    const { apiGet } = await import("./api");
    await expect(apiGet("/me")).rejects.toThrow();
    expect(assign).toHaveBeenCalledWith(`/login?next=${encodeURIComponent("/grc/objects?project=p1")}`);
    expect(sessionStorage.getItem("platform.token")).toBeNull();
  });

  it("403 no_product_roles — событие для экрана «Нет доступа», без refresh", async () => {
    sessionStorage.setItem("platform.token", "tok");
    const fetchMock = vi.fn(async () => json(403, { detail: "no_product_roles" }));
    vi.stubGlobal("fetch", fetchMock);
    const { apiGet, NO_ROLES_EVENT } = await import("./api");
    const seen = vi.fn();
    window.addEventListener(NO_ROLES_EVENT, seen);
    await expect(apiGet("/me")).rejects.toThrow("Нет доступа к «Аттестации»");
    window.removeEventListener(NO_ROLES_EVENT, seen);
    expect(seen).toHaveBeenCalledOnce();
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("выход: отзыв refresh, сигнал другим вкладкам, страница входа", async () => {
    sessionStorage.setItem("platform.token", "tok");
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);
    const { platformLogout } = await import("./platform");
    await platformLogout();
    expect(fetchMock).toHaveBeenCalledWith("/api/platform/auth/logout", expect.objectContaining({ method: "POST" }));
    expect(sessionStorage.getItem("platform.token")).toBeNull();
    expect(Number(localStorage.getItem("platform.logout"))).toBeGreaterThan(0);
    expect(assign).toHaveBeenCalledWith("/login");
  });
});

describe("отдельный запуск", () => {
  it("ссылок на соседей нет", async () => {
    vi.resetModules();
    const { productLink, PLATFORM } = await import("./platform");
    expect(PLATFORM).toBe(false);
    expect(productLink("vm", "tickets/1", "p")).toBeNull();
  });
});
