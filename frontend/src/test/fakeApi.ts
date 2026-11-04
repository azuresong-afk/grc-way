// Подмена fetch в тестах: маршруты «МЕТОД путь» → обработчик.
type Handler = (init: RequestInit | undefined, url: URL) => Response | Promise<Response>;

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

export function fakeApi(routes: Record<string, Handler>) {
  const calls: { method: string; path: string; body: unknown; auth: string | null }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://test");
    const method = (init?.method ?? "GET").toUpperCase();
    const path = url.pathname.replace(/^\/api/, "");
    const headers = new Headers(init?.headers);
    calls.push({
      method,
      path,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
      auth: headers.get("Authorization"),
    });
    const handler = routes[`${method} ${path}`];
    if (!handler) return json({ detail: `нет маршрута ${method} ${path}` }, 404);
    return handler(init, url);
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}
