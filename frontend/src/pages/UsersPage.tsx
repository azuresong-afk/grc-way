import { Pencil, UserPlus, Users } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { Pager } from "../components/Pager";
import { ErrorAlert, Loading } from "../components/Status";
import { apiPage, apiSend, query } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDateTime } from "../lib/format";
import { ROLE_HINTS, ROLE_ORDER, ROLE_TITLES, roleList } from "../lib/roles";

interface User {
  id: string;
  username: string;
  display_name: string;
  roles: string[];
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

const LIMIT = 50;

export function UsersPage() {
  const [items, setItems] = useState<User[] | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<User | "new" | null>(null);

  const load = useCallback(() => {
    setError(null);
    apiPage<User>(`/users${query({ limit: LIMIT, offset })}`)
      .then((p) => {
        setItems(p.items);
        setTotal(p.total);
      })
      .catch((e: Error) => setError(e.message));
  }, [offset]);

  useEffect(load, [load]);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">Администрирование</div>
          <h1>Пользователи и роли</h1>
        </div>
        <div className="actions">
          <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}>
            <UserPlus size={15} />
            Добавить пользователя
          </button>
        </div>
      </div>

      {error && <ErrorAlert message={error} onRetry={load} />}

      <section className="card">
        {items === null && !error && <Loading />}
        {items?.length === 0 && (
          <EmptyState icon={<Users size={21} />} title="Пользователей нет" text="Добавьте первого." />
        )}
        {items && items.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Пользователь</th>
                  <th>Роли</th>
                  <th>Состояние</th>
                  <th>Последний вход</th>
                  <th aria-label="Действия" />
                </tr>
              </thead>
              <tbody>
                {items.map((u) => (
                  <tr key={u.id}>
                    <td>
                      <div className="cell-title">{u.display_name}</div>
                      <div className="cell-sub mono">{u.username}</div>
                    </td>
                    <td>{roleList(u.roles)}</td>
                    <td>
                      {u.is_active ? (
                        <span className="pill pill-ok">Активен</span>
                      ) : (
                        <span className="pill pill-muted">Заблокирован</span>
                      )}
                    </td>
                    <td>{formatDateTime(u.last_login_at)}</td>
                    <td className="cell-actions">
                      <button
                        type="button"
                        className="icon-btn"
                        aria-label={`Изменить ${u.display_name}`}
                        onClick={() => setEditing(u)}
                      >
                        <Pencil size={15} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pager total={total} limit={LIMIT} offset={offset} onChange={setOffset} />
      </section>

      {editing && (
        <UserDialog
          user={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            load();
          }}
        />
      )}
    </>
  );
}

function UserDialog({
  user,
  onClose,
  onSaved,
}: {
  user: User | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { me } = useAuth();
  const isSelf = user?.id === me?.id;
  const [username, setUsername] = useState(user?.username ?? "");
  const [displayName, setDisplayName] = useState(user?.display_name ?? "");
  const [password, setPassword] = useState("");
  const [roles, setRoles] = useState<Set<string>>(new Set(user?.roles ?? []));
  const [active, setActive] = useState(user?.is_active ?? true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function toggle(role: string) {
    setRoles((prev) => {
      const next = new Set(prev);
      if (next.has(role)) next.delete(role);
      else next.add(role);
      return next;
    });
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (user) {
        await apiSend("PATCH", `/users/${user.id}`, {
          display_name: displayName,
          roles: [...roles],
          is_active: active,
          ...(password ? { password } : {}),
        });
      } else {
        await apiSend("POST", "/users", {
          username,
          display_name: displayName,
          password,
          roles: [...roles],
        });
      }
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось сохранить");
    } finally {
      setBusy(false);
    }
  }

  const formId = "user-form";
  return (
    <Modal
      title={user ? "Изменить пользователя" : "Новый пользователь"}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={busy}>
            {user ? "Сохранить" : "Создать"}
          </button>
        </>
      }
    >
      <form id={formId} className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <label className="field">
          <span>Имя пользователя</span>
          <input
            className="input mono"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={!!user}
            required
            pattern="[A-Za-z0-9._\-]+"
            autoComplete="off"
          />
          {!user && <small>Латиница, цифры, точка, дефис, подчёркивание</small>}
        </label>
        <label className="field">
          <span>ФИО</span>
          <input
            className="input"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            required
          />
        </label>
        <label className="field">
          <span>{user ? "Новый пароль" : "Пароль"}</span>
          <input
            className="input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required={!user}
            minLength={12}
            autoComplete="new-password"
          />
          <small>{user ? "Оставьте пустым, чтобы не менять. " : ""}Не короче 12 символов</small>
        </label>
        <fieldset className="field check-list">
          <span>Роли</span>
          {ROLE_ORDER.map((r) => (
            <label key={r} className="check">
              <input
                type="checkbox"
                checked={roles.has(r)}
                onChange={() => toggle(r)}
                disabled={isSelf && r === "admin"}
              />
              <span>
                <b>{ROLE_TITLES[r]}</b>
                <small>{ROLE_HINTS[r]}</small>
              </span>
            </label>
          ))}
        </fieldset>
        {user && !isSelf && (
          <label className="check">
            <input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} />
            <span>
              <b>Активен</b>
              <small>Заблокированный пользователь не может войти; действует сразу</small>
            </span>
          </label>
        )}
      </form>
    </Modal>
  );
}
