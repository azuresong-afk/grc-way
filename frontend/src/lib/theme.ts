// Тема — одна настройка на все продукты платформы: ключ platform.theme.
// У «Сканера» исторически scanner.theme — читаем оба.
export type Theme = "dark" | "light";

export const THEME_KEY = "platform.theme";
const LEGACY_KEYS = ["scanner.theme"];

function read(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function loadTheme(): Theme {
  for (const key of [THEME_KEY, ...LEGACY_KEYS]) {
    const v = read(key);
    if (v === "light" || v === "dark") return v;
  }
  return "dark";
}

export function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  if (theme === "light") root.setAttribute("data-theme", "light");
  else root.removeAttribute("data-theme");
}

export function saveTheme(theme: Theme): void {
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {
    // Хранилище недоступно (приватный режим) — тема живёт до перезагрузки.
  }
}
