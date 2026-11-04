import {
  BookOpen,
  FolderKanban,
  LayoutDashboard,
  LogOut,
  Menu,
  ScrollText,
  Search,
  Server,
  ShieldCheck,
  Users,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { initials } from "../lib/format";
import { roleList } from "../lib/roles";
import { ProjectPicker } from "./ProjectPicker";
import { ThemeToggle } from "./ThemeToggle";

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  perm?: string;
}

// Пункты меню добавляются вместе с экранами (см. docs/roadmap.md, этап 1).
const NAV: NavItem[] = [
  { to: "/summary", label: "Сводка", icon: <LayoutDashboard size={18} /> },
  { to: "/projects", label: "Проекты", icon: <FolderKanban size={18} />, perm: "view" },
  { to: "/objects", label: "Объекты", icon: <Server size={18} />, perm: "view" },
  { to: "/refs", label: "Справочники", icon: <BookOpen size={18} /> },
];

const ADMIN_NAV: NavItem[] = [
  { to: "/admin/users", label: "Пользователи и роли", icon: <Users size={18} />, perm: "users.manage" },
  { to: "/admin/audit", label: "Журнал аудита", icon: <ScrollText size={18} />, perm: "audit.view" },
];

function NavItems({ items }: { items: NavItem[] }) {
  return items.map((item) => (
    <NavLink
      key={item.to}
      to={item.to}
      className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}
    >
      {item.icon}
      {item.label}
    </NavLink>
  ));
}

export function Layout() {
  const { me, can, logout } = useAuth();
  const [navOpen, setNavOpen] = useState(false);
  const location = useLocation();

  useEffect(() => setNavOpen(false), [location.pathname]);

  const adminItems = ADMIN_NAV.filter((i) => !i.perm || can(i.perm));

  return (
    <div className={`shell${navOpen ? " nav-open" : ""}`}>
      <aside className="sidebar" aria-label="Главное меню">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            <ShieldCheck size={18} />
          </div>
          <div>
            <div className="brand-name">Аттестация</div>
            <div className="brand-sub">соответствие ФСТЭК</div>
          </div>
        </div>
        <nav className="nav">
          <NavItems items={NAV.filter((i) => !i.perm || can(i.perm))} />
          {adminItems.length > 0 && (
            <>
              <div className="nav-group-title">Администрирование</div>
              <NavItems items={adminItems} />
            </>
          )}
        </nav>
        <div className="sidebar-foot">
          {me && (
            <div className="user-card">
              <div className="avatar" aria-hidden="true">
                {initials(me.display_name)}
              </div>
              <div className="user-meta">
                <div className="user-name">{me.display_name}</div>
                <div className="user-roles">{roleList(me.roles)}</div>
              </div>
              <button type="button" className="icon-btn" aria-label="Выйти" title="Выйти" onClick={logout}>
                <LogOut size={15} />
              </button>
            </div>
          )}
          <ThemeToggle />
        </div>
      </aside>
      <div className="backdrop" onClick={() => setNavOpen(false)} aria-hidden="true" />
      <div className="main">
        <header className="topbar">
          <button
            type="button"
            className="icon-btn topbar-burger"
            aria-label="Открыть меню"
            onClick={() => setNavOpen(true)}
          >
            <Menu size={18} />
          </button>
          <ProjectPicker />
          <button type="button" className="topbar-search" disabled title="Поиск появится позже">
            <Search size={15} />
            Поиск
            <kbd>Ctrl K</kbd>
          </button>
          <span className="topbar-note">Работы ведутся в рамках договора</span>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
