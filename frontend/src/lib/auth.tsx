import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { apiGet, apiSend, getToken, setToken, UNAUTHORIZED_EVENT } from "./api";

export interface Me {
  id: string;
  username: string;
  display_name: string;
  roles: string[];
  permissions: string[];
}

interface AuthState {
  me: Me | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (perm: string) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(() => getToken() !== null);

  useEffect(() => {
    if (!getToken()) return;
    apiGet<Me>("/me")
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const onExpired = () => setMe(null);
    window.addEventListener(UNAUTHORIZED_EVENT, onExpired);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onExpired);
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
    <AuthContext.Provider value={{ me, loading, login, logout, can }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth вне AuthProvider");
  return ctx;
}

/** Без входа — на /login?next=<текущий путь>. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { me, loading } = useAuth();
  const location = useLocation();
  if (loading) {
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
