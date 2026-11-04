// Префикс API: в отдельном запуске «/api», в платформе «/api/grc».
export const API_BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "/api";

// Токен — в sessionStorage под общим ключом платформы (контракт v1, п. 2).
export const TOKEN_KEY = "platform.token";

export function getToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // Хранилище недоступно — вход продлится до перезагрузки вкладки.
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/** Событие «сессия кончилась»: слушает AuthProvider и уводит на вход. */
export const UNAUTHORIZED_EVENT = "grc:unauthorized";

async function errorMessage(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { detail?: unknown };
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) return "Проверьте заполнение полей";
  } catch {
    // тело не JSON
  }
  if (res.status >= 500) return "Ошибка сервера. Повторите позже";
  return `Сервер ответил ${res.status}`;
}

export interface Page<T> {
  items: T[];
  total: number;
}

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body && typeof init.body === "string") headers.set("Content-Type", "application/json");
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (res.status === 401 && token) {
    setToken(null);
    window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
  }
  if (!res.ok) throw new ApiError(res.status, await errorMessage(res));
  return res;
}

export async function apiGet<T>(path: string): Promise<T> {
  return (await (await apiFetch(path)).json()) as T;
}

export async function apiPage<T>(path: string): Promise<Page<T>> {
  const res = await apiFetch(path);
  const items = (await res.json()) as T[];
  return { items, total: Number(res.headers.get("X-Total-Count") ?? items.length) };
}

export async function apiSend<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await apiFetch(path, {
    method,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export function query(params: Record<string, string | number | undefined | null>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}
