import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { apiGet, apiSend, getToken, NO_ROLES_EVENT, setToken, UNAUTHORIZED_EVENT } from "./api";
import { LOGOUT_KEY, PLATFORM, goToLogin, platformLogout, refreshToken } from "./platform";

export interface Me {
  id: string;
  username: string;
  display_name: string;
  roles: string[];
  permissions: string[];
  auth_mode?: "local" | "platform";
  service?: boolean;
}

interface AuthState {
  me: Me | null;
  loading: boolean;
  /** Режим платформы: у пользователя нет ролей в «Аттестации». */
  noRoles: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (perm: string) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(() => PLATFORM || getToken() !== null);
  const [noRoles, setNoRoles] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      // Платформа: токена во вкладке ещё нет — тихий refresh по cookie, иначе вход оболочки.
      if (PLATFORM && !getToken() && !(await refreshToken())) {
        goToLogin();
        return;
      }
      if (!getToken()) return;
      try {
        const m = await apiGet<Me>("/me");
        if (!cancelled) setMe(m);
      } catch {
        if (!cancelled) setMe(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const onExpired = () => setMe(null);
    const onNoRoles = () => {
      setNoRoles(true);
      setLoading(false);
    };
    // Выход в другой вкладке любого продукта платформы (контракт v1.1, п. 2.4).
    const onStorage = (e: StorageEvent) => {
      if (PLATFORM && e.key === LOGOUT_KEY && e.newValue) {
        setToken(null);
        goToLogin();
      }
    };
    window.addEventListener(UNAUTHORIZED_EVENT, onExpired);
    window.addEventListener(NO_ROLES_EVENT, onNoRoles);
    window.addEventListener("storage", onStorage);
    return () => {
      window.removeEventListener(UNAUTHORIZED_EVENT, onExpired);
      window.removeEventListener(NO_ROLES_EVENT, onNoRoles);
      window.removeEventListener("storage", onStorage);
    };
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const tok = await apiSend<{ access_token: string }>("POST", "/auth/token", {
      username,
      password,
    });
    setToken(tok.access_token);
    setMe(await apiGet<Me>("/me"));
  }, []);

  const logout = useCallback(async () => {
    if (PLATFORM) {
      await platformLogout();
      return;
    }
    try {
      await apiSend("POST", "/auth/logout");
    } catch {
      // токен мог уже истечь — выходим всё равно
    }
    setToken(null);
    setMe(null);
  }, []);

  const can = useCallback((perm: string) => me?.permissions.includes(perm) ?? false, [me]);

  return (
    <AuthContext.Provider value={{ me, loading, noRoles, login, logout, can }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth вне AuthProvider");
  return ctx;
}

/** Экран «Нет доступа к продукту» (контракт v1.1, п. 2.1): ролей в «Аттестации» нет. */
export function NoProductAccess() {
  return (
    <div className="login-page">
      <div className="card login-card" role="alert">
        <h1 className="login-title">Нет доступа к «Аттестации»</h1>
        <p className="muted">
          В «Платформе» вам не выданы роли этого продукта. Обратитесь к администратору платформы.
        </p>
        <a className="btn btn-primary" href="/">
          На главную платформы
        </a>
      </div>
    </div>
  );
}

/** Без входа — на /login?next=<текущий путь> (в платформе — на вход оболочки). */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { me, loading, noRoles } = useAuth();
  const location = useLocation();
  if (noRoles) return <NoProductAccess />;
  if (loading || (PLATFORM && !me)) {
    return (
      <div className="loading">
        <span className="spinner" aria-hidden="true" /> Загрузка…
      </div>
    );
  }
  if (!me) {
    const next = location.pathname + location.search;
    return <Navigate to={`/login?next=${encodeURIComponent(next)}`} replace />;
  }
  return <>{children}</>;
}

/** Раздел только для владельцев права; иначе — сообщение без утечки содержимого. */
export function RequirePerm({ perm, children }: { perm: string; children: ReactNode }) {
  const { can } = useAuth();
  if (!can(perm)) {
    return (
      <div className="alert alert-warn" role="alert">
        Недостаточно прав для этого раздела.
      </div>
    );
  }
  return <>{children}</>;
}
