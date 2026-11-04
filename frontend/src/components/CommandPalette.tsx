import {
  BookOpen,
  Bug,
  CornerDownLeft,
  FolderKanban,
  LayoutDashboard,
  ListChecks,
  Monitor,
  RefreshCw,
  ScrollText,
  Search,
  Server,
  ShieldAlert,
  Table2,
  Users,
} from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { apiGet } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { SearchItem, SearchKind } from "../lib/summary";

interface Action {
  id: string;
  label: string;
  hint: string;
  to: string;
  icon: ReactNode;
  perm?: string;
}

// Действия палитры — переходы к разделам; права те же, что у пунктов меню.
const ACTIONS: Action[] = [
  { id: "summary", label: "Сводка", hint: "показатели проекта", to: "/summary", icon: <LayoutDashboard size={15} /> },
  { id: "objects", label: "Объекты", hint: "ГИС, ИСПДн, КИИ", to: "/objects", icon: <Server size={15} />, perm: "view" },
  { id: "projects", label: "Проекты", hint: "договоры и участники", to: "/projects", icon: <FolderKanban size={15} />, perm: "view" },
  { id: "refs", label: "Справочник мер", hint: "профили и сверка", to: "/refs", icon: <BookOpen size={15} /> },
  { id: "tables", label: "Таблицы классификации", hint: "№117, №21, №239", to: "/refs/classification", icon: <Table2 size={15} /> },
  { id: "threats", label: "Методика оценки угроз", hint: "У1–У3, Н1–Н4, тактики", to: "/refs/threats", icon: <ShieldAlert size={15} /> },
  { id: "bdu", label: "БДУ ФСТЭК России", hint: "угрозы УБИ и уязвимости", to: "/refs/bdu", icon: <Bug size={15} /> },
  { id: "scanner", label: "Обновить справочник из «Сканера»", hint: "сравнение профилей", to: "/refs/scanner", icon: <RefreshCw size={15} />, perm: "refs.manage" },
  { id: "users", label: "Пользователи и роли", hint: "администрирование", to: "/admin/users", icon: <Users size={15} />, perm: "users.manage" },
  { id: "audit", label: "Журнал аудита", hint: "администрирование", to: "/admin/audit", icon: <ScrollText size={15} />, perm: "audit.view" },
];

const KIND_TITLES: Record<SearchKind, string> = {
  project: "Проекты",
  object: "Объекты",
  host: "Хосты",
  measure: "Меры объектов",
};

const KIND_ICONS: Record<SearchKind, ReactNode> = {
  project: <FolderKanban size={15} />,
  object: <Server size={15} />,
  host: <Monitor size={15} />,
  measure: <ListChecks size={15} />,
};

interface Option {
  key: string;
  group: string;
  label: string;
  hint: string | null;
  icon: ReactNode;
  to: string;
}

function fold(s: string): string {
  return s.toLocaleLowerCase("ru-RU").replace(/ё/g, "е");
}

/** Быстрый поиск Ctrl+K: разделы продукта и записи (проекты, объекты, хосты, меры). */
export function CommandPalette({ onClose }: { onClose: () => void }) {
  const { can } = useAuth();
  const navigate = useNavigate();
  const listId = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const [q, setQ] = useState("");
  const [found, setFound] = useState<SearchItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [failed, setFailed] = useState(false);
  const [active, setActive] = useState(0);

  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    inputRef.current?.focus();
    return () => prev?.focus();
  }, []);

  // Поиск по записям — с задержкой, ответы на устаревший запрос отбрасываются.
  useEffect(() => {
    const text = q.trim();
    if (text.length < 2 || !can("view")) {
      setFound([]);
      setLoading(false);
      setFailed(false);
      return;
    }
    let alive = true;
    setLoading(true);
    const t = window.setTimeout(() => {
      apiGet<{ items: SearchItem[] }>(`/search?q=${encodeURIComponent(text)}`)
        .then((r) => {
          if (!alive) return;
          setFound(r.items);
          setFailed(false);
        })
        .catch(() => alive && setFailed(true))
        .finally(() => alive && setLoading(false));
    }, 180);
    return () => {
      alive = false;
      window.clearTimeout(t);
    };
  }, [q, can]);

  const options = useMemo<Option[]>(() => {
    const needle = fold(q.trim());
    const actions = ACTIONS.filter((a) => !a.perm || can(a.perm))
      .filter((a) => !needle || fold(`${a.label} ${a.hint}`).includes(needle))
      .map((a) => ({
        key: `action:${a.id}`,
        group: "Перейти",
        label: a.label,
        hint: a.hint,
        icon: a.icon,
        to: a.to,
      }));
    const records = found.map((r) => ({
      key: `${r.kind}:${r.id}`,
      group: KIND_TITLES[r.kind],
      label: r.title,
      hint: r.subtitle,
      icon: KIND_ICONS[r.kind],
      to: r.path,
    }));
    // Сначала записи: при поиске нужнее они; без запроса — только действия.
    return [...records, ...actions];
  }, [q, found, can]);

  useEffect(() => setActive(0), [options]);

  const go = (o: Option | undefined) => {
    if (!o) return;
    onClose();
    navigate(o.to);
  };

  const onKey = (e: KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => (options.length ? (i + 1) % options.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => (options.length ? (i - 1 + options.length) % options.length : 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      go(options[active]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  };

  useEffect(() => {
    document.getElementById(`${listId}-${active}`)?.scrollIntoView?.({ block: "nearest" });
  }, [active, listId]);

  const text = q.trim();
  let lastGroup = "";
  return (
    <div className="palette-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Быстрый поиск">
        <div className="palette-input">
          <Search size={16} aria-hidden="true" />
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-expanded="true"
            aria-controls={listId}
            aria-activedescendant={options.length ? `${listId}-${active}` : undefined}
            aria-autocomplete="list"
            aria-label="Что найти"
            placeholder="Объект, хост, мера (УПД.3) или раздел…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKey}
          />
          {loading && <span className="spinner" aria-label="Поиск…" />}
          <kbd>Esc</kbd>
        </div>
        <ul className="palette-list" id={listId} role="listbox" aria-label="Результаты">
          {options.map((o, i) => {
            const head = o.group !== lastGroup ? o.group : null;
            lastGroup = o.group;
            return (
              <li key={o.key} role="presentation">
                {head && (
                  <div className="palette-group" aria-hidden="true">
                    {head}
                  </div>
                )}
                <div
                  id={`${listId}-${i}`}
                  role="option"
                  aria-selected={i === active}
                  className={`palette-option${i === active ? " active" : ""}`}
                  onMouseMove={() => setActive(i)}
                  onClick={() => go(o)}
                >
                  <span className="palette-icon" aria-hidden="true">
                    {o.icon}
                  </span>
                  <span className="palette-text">
                    <span className="palette-label">{o.label}</span>
                    {o.hint && <span className="palette-hint">{o.hint}</span>}
                  </span>
                  {i === active && <CornerDownLeft size={13} className="palette-enter" aria-hidden="true" />}
                </div>
              </li>
            );
          })}
        </ul>
        {options.length === 0 && (
          <div className="palette-empty">
            {loading ? "Ищем…" : failed ? "Поиск недоступен — проверьте связь с сервером" : `Ничего не найдено по «${text}»`}
          </div>
        )}
        {failed && options.length > 0 && (
          <div className="palette-foot">Поиск по записям недоступен — показаны только разделы</div>
        )}
        {!failed && text.length === 1 && can("view") && (
          <div className="palette-foot">Для поиска по объектам, хостам и мерам введите хотя бы 2 символа</div>
        )}
      </div>
    </div>
  );
}
