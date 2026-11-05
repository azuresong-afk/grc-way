import { PLATFORM, TOKEN_KEY, goToLogin, refreshToken } from "./platform";

// Префикс API: в отдельном запуске «/api», в платформе «/api/grc».
export const API_BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? "/api";

// Токен — в sessionStorage под общим ключом платформы (контракт v1, п. 2).
export { TOKEN_KEY };

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
/** Режим платформы: у пользователя нет ролей в «Аттестации» (403 no_product_roles). */
export const NO_ROLES_EVENT = "grc:no-product-roles";

// Коды платформы (контракт v1.1, п. 2–3) — по-русски.
const CODES: Record<string, string> = {
  not_authenticated: "Требуется вход",
  invalid_token: "Сессия истекла, войдите снова",
  no_product_roles: "Нет доступа к «Аттестации»",
  no_project_access: "Нет доступа к этому проекту",
  project_archived: "Проект в архиве — только просмотр",
};

async function errorMessage(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { detail?: unknown };
    if (typeof body.detail === "string") return CODES[body.detail] ?? body.detail;
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

async function detailOf(res: Response): Promise<string | null> {
  try {
    const body = (await res.clone().json()) as { detail?: unknown };
    return typeof body.detail === "string" ? body.detail : null;
  } catch {
    return null;
  }
}

export async function apiFetch(path: string, init: RequestInit = {}, retried = false): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body && typeof init.body === "string") headers.set("Content-Type", "application/json");
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (res.status === 401 && PLATFORM) {
    // Один тихий refresh на вкладку и повтор; не вышло — на вход оболочки.
    if (!retried && (await refreshToken())) return apiFetch(path, init, true);
    setToken(null);
    goToLogin();
    throw new ApiError(401, "Требуется вход");
  }
  if (res.status === 401 && token) {
    setToken(null);
    window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
  }
  if (res.status === 403 && PLATFORM && (await detailOf(res)) === "no_product_roles") {
    window.dispatchEvent(new Event(NO_ROLES_EVENT));
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
