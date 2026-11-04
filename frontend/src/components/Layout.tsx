import { LayoutDashboard, Menu, Search, ShieldCheck } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { ThemeToggle } from "./ThemeToggle";

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
}

// Пункты меню добавляются вместе с экранами (см. docs/roadmap.md, этап 1).
const NAV: NavItem[] = [{ to: "/summary", label: "Сводка", icon: <LayoutDashboard size={18} /> }];

export function Layout() {
  const [navOpen, setNavOpen] = useState(false);
  const location = useLocation();

  useEffect(() => setNavOpen(false), [location.pathname]);

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
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}
            >
              {item.icon}
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
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
