import { Bell, BookOpen, Building2, Home, LayoutGrid, ShieldCheck, Wrench, Radar } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { getToken } from "../lib/api";
import { PLATFORM_API } from "../lib/platform";
import { useProject } from "../lib/project";

interface TabProduct {
  id: string;
  title: string;
  icon?: string;
  base_path: string;
}

// Иконки манифестов соседей; неизвестная — общая.
const ICONS: Record<string, ReactNode> = {
  "shield-check": <ShieldCheck size={15} aria-hidden="true" />,
  wrench: <Wrench size={15} aria-hidden="true" />,
  radar: <Radar size={15} aria-hidden="true" />,
  "building-2": <Building2 size={15} aria-hidden="true" />,
  "book-open": <BookOpen size={15} aria-hidden="true" />,
};

function withProject(href: string, projectId: string | null | undefined): string {
  if (!projectId) return href;
  return `${href}${href.includes("?") ? "&" : "?"}project=${encodeURIComponent(projectId)}`;
}

async function platformJson<T>(path: string): Promise<T> {
  const token = getToken();
  const res = await fetch(`${PLATFORM_API}${path}`, {
    headers: { Accept: "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    credentials: "same-origin",
  });
  if (!res.ok) throw new Error(String(res.status));
  return (await res.json()) as T;
}

/**
 * Строка вкладок продуктов платформы (VITE_PLATFORM=1), как `PlatformTabs` из
 * `@platform/ui`: продукты с ролями пользователя (GET /api/platform/products),
 * колокольчик уведомлений платформы. Переход — обычная ссылка: другие SPA того же origin.
 */
export function PlatformTabs() {
  const { current } = useProject();
  const [products, setProducts] = useState<TabProduct[]>([]);
  const [unread, setUnread] = useState(0);
  const activeRef = useRef<HTMLAnchorElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    platformJson<TabProduct[]>("/products")
      .then((items) => !cancelled && setProducts(Array.isArray(items) ? items : []))
      .catch(() => !cancelled && setProducts([]));
    const poll = () =>
      platformJson<{ unread: number }>("/notifications/unread-count")
        .then((r) => !cancelled && setUnread(typeof r?.unread === "number" ? r.unread : 0))
        .catch(() => undefined);
    poll();
    const timer = window.setInterval(poll, 60_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  // На телефоне строка прокручивается: своя вкладка — в поле зрения.
  useEffect(() => {
    activeRef.current?.scrollIntoView?.({ block: "nearest", inline: "nearest" });
  }, [products]);

  const projectId = current?.platform_project_id ?? current?.id ?? null;
  // Своя вкладка есть всегда: пользователь здесь, значит роль у него есть.
  const list = products.some((p) => p.id === "grc")
    ? products
    : [...products, { id: "grc", title: "Аттестация", icon: "shield-check", base_path: "/grc/" }];

  return (
    <nav className="product-tabs" aria-label="Продукты">
      <div className="product-tabs-list">
        <a className="tab" href={withProject("/", projectId)}>
          <Home size={15} aria-hidden="true" />
          Главная
        </a>
        {list.map((p) => (
          <a
            key={p.id}
            className={`tab${p.id === "grc" ? " active" : ""}`}
            href={withProject(p.base_path, projectId)}
            aria-current={p.id === "grc" ? "page" : undefined}
            ref={p.id === "grc" ? activeRef : undefined}
            data-product={p.id}
          >
            {ICONS[p.icon ?? ""] ?? <LayoutGrid size={15} aria-hidden="true" />}
            {p.title}
          </a>
        ))}
      </div>
      <div className="product-tabs-right">
        <a
          className="icon-btn notif-bell"
          href="/notifications"
          aria-label={unread ? `Уведомления: ${unread} непрочитанных` : "Уведомления"}
          title="Уведомления"
        >
          <Bell size={16} aria-hidden="true" />
          {unread > 0 && <span className="notif-count">{unread > 99 ? "99+" : unread}</span>}
        </a>
      </div>
    </nav>
  );
}
