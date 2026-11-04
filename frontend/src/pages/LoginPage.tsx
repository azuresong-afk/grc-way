import { LogIn, ShieldCheck } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { ErrorAlert } from "../components/Status";
import { useAuth } from "../lib/auth";

// Разрешаем только внутренние пути: «//evil» и «https://…» — открытый редирект.
function safeNext(next: string | null): string {
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/summary";
}

export function LoginPage() {
  const { me, login } = useAuth();
  const [params] = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (me) return <Navigate to={safeNext(params.get("next"))} replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username.trim(), password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось войти");
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <form className="card login-card" onSubmit={submit}>
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            <ShieldCheck size={18} />
          </div>
          <div>
            <div className="brand-name">Аттестация</div>
            <div className="brand-sub">соответствие ФСТЭК</div>
          </div>
        </div>
        <h1>Вход</h1>
        {error && <ErrorAlert message={error} />}
        <label className="field">
          <span>Имя пользователя</span>
          <input
            className="input"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </label>
        <label className="field">
          <span>Пароль</span>
          <input
            className="input"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </label>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          <LogIn size={15} />
          {busy ? "Вход…" : "Войти"}
        </button>
      </form>
    </div>
  );
}
