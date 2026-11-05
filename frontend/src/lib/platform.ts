// Режим «Платформы» (задача 3.5, контракт v1.1, п. 2.4, 7, 11).
// VITE_PLATFORM=1 — SPA собрана для работы вкладкой оболочки: своего входа нет,
// токен выдаёт платформа, над интерфейсом — строка вкладок продуктов.

const flag = import.meta.env.VITE_PLATFORM as string | undefined;
export const PLATFORM = flag === "1" || flag === "true";

// API платформы для браузера (шлюз отрезает префикс).
export const PLATFORM_API = (import.meta.env.VITE_PLATFORM_API as string | undefined) ?? "/api/platform";

export const TOKEN_KEY = "platform.token";
export const LOGOUT_KEY = "platform.logout";

/** Путь с query для ?next= — с base_path SPA (в платформе /grc/…). */
export function currentPath(): string {
  return window.location.pathname + window.location.search;
}

/** Вход — страница оболочки, не наша. */
export function goToLogin(next: string = currentPath()): void {
  window.location.assign(`/login?next=${encodeURIComponent(next)}`);
}

function storeToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // хранилище недоступно
  }
}

let refreshing: Promise<string | null> | null = null;

/** Один общий на вкладку тихий refresh по httpOnly-cookie платформы. */
export function refreshToken(): Promise<string | null> {
  if (!refreshing) {
    refreshing = (async () => {
      try {
        const res = await fetch(`${PLATFORM_API}/auth/refresh`, {
          method: "POST",
          credentials: "same-origin",
          headers: { Accept: "application/json" },
        });
        if (!res.ok) return null;
        const body = (await res.json()) as { access_token?: string };
        const token = body.access_token ?? null;
        storeToken(token);
        return token;
      } catch {
        return null;
      } finally {
        // Следующий 401 (через 15 минут) — новый refresh.
        setTimeout(() => {
          refreshing = null;
        }, 0);
      }
    })();
  }
  return refreshing;
}

/** Выход отовсюду: отзыв refresh-cookie, сигнал другим вкладкам, страница входа. */
export async function platformLogout(): Promise<void> {
  try {
    await fetch(`${PLATFORM_API}/auth/logout`, { method: "POST", credentials: "same-origin" });
  } catch {
    // выходим всё равно
  }
  storeToken(null);
  try {
    localStorage.setItem(LOGOUT_KEY, String(Date.now()));
  } catch {
    // без сигнала другие вкладки уйдут по истечении токена
  }
  window.location.assign("/login");
}

export type Product = "scanner" | "vm" | "grc";

/**
 * Межпродуктовая ссылка того же origin: /<product>/<route>?project=<uuid> (контракт, п. 7).
 * Вне платформы соседей по адресу не знаем — null.
 */
export function productLink(product: Product, route: string, projectId?: string | null): string | null {
  if (!PLATFORM) return null;
  const path = `/${product}/${route.replace(/^\/+/, "")}`;
  if (!projectId) return path;
  return `${path}${path.includes("?") ? "&" : "?"}project=${encodeURIComponent(projectId)}`;
}
