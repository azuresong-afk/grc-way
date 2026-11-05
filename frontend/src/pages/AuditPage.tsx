import { Download, ScrollText } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { EmptyState } from "../components/EmptyState";
import { Pager } from "../components/Pager";
import { ErrorAlert, Loading } from "../components/Status";
import { apiFetch, apiPage, query } from "../lib/api";
import { formatDateTime } from "../lib/format";

interface AuditRecord {
  id: number;
  at: string;
  user_name: string | null;
  action: string;
  entity: string | null;
  entity_id: string | null;
  result: string;
  ip: string | null;
  details: Record<string, unknown>;
}

const LIMIT = 50;

export const ACTION_TITLES: Record<string, string> = {
  "auth.login": "Вход",
  "auth.logout": "Выход",
  "access.denied": "Отказ в доступе",
  "user.create": "Создание пользователя",
  "user.update": "Изменение пользователя",
  "user.bootstrap": "Создание первого администратора",
  "audit.export": "Выгрузка журнала",
  "user.shadow_create": "Первый вход из «Платформы»",
  "project.shadow_create": "Проект из «Платформы»",
  "project.shadow_sync": "Сверка проекта с «Платформой»",
  "platform.keys_rotated": "Смена ключей «Платформы»",
  "platform.outbox_retry": "Повторная отправка события",
};

const RESULT_PILL: Record<string, [string, string]> = {
  ok: ["pill-ok", "Успешно"],
  denied: ["pill-warn", "Отказано"],
  error: ["pill-danger", "Ошибка"],
};

const FILTERS: [string, string][] = [
  ["", "Все"],
  ["denied", "Отказы"],
];

export function AuditPage() {
  const [items, setItems] = useState<AuditRecord[] | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [result, setResult] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setError(null);
    apiPage<AuditRecord>(`/audit${query({ limit: LIMIT, offset, result })}`)
      .then((p) => {
        setItems(p.items);
        setTotal(p.total);
      })
      .catch((e: Error) => setError(e.message));
  }, [offset, result]);

  useEffect(load, [load]);

  async function exportCsv() {
    try {
      const res = await apiFetch(`/audit/export${query({ result })}`);
      const url = URL.createObjectURL(await res.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = "audit.csv";
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось выгрузить журнал");
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">Администрирование</div>
          <h1>Журнал аудита</h1>
        </div>
        <div className="actions">
          <button type="button" className="btn" onClick={exportCsv}>
            <Download size={15} />
            Выгрузить CSV
          </button>
        </div>
      </div>

      <div className="chips" role="group" aria-label="Результат">
        {FILTERS.map(([value, label]) => (
          <button
            key={value}
            type="button"
            className="chip"
            aria-pressed={result === value}
            onClick={() => {
              setResult(value);
              setOffset(0);
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {error && <ErrorAlert message={error} onRetry={load} />}

      <section className="card">
        {items === null && !error && <Loading />}
        {items?.length === 0 && (
          <EmptyState
            icon={<ScrollText size={21} />}
            title="Записей нет"
            text="Под выбранный фильтр ничего не попало."
          />
        )}
        {items && items.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Время</th>
                  <th>Пользователь</th>
                  <th>Действие</th>
                  <th>Результат</th>
                  <th>IP</th>
                  <th>Подробности</th>
                </tr>
              </thead>
              <tbody>
                {items.map((r) => {
                  const [cls, label] = RESULT_PILL[r.result] ?? ["pill-muted", r.result];
                  return (
                    <tr key={r.id}>
                      <td className="nowrap">{formatDateTime(r.at)}</td>
                      <td>{r.user_name ?? "—"}</td>
                      <td>
                        {ACTION_TITLES[r.action] ?? r.action}
                        <div className="cell-sub mono">{r.action}</div>
                      </td>
                      <td>
                        <span className={`pill ${cls}`}>{label}</span>
                      </td>
                      <td className="mono">{r.ip ?? "—"}</td>
                      <td className="cell-details mono">
                        {Object.keys(r.details).length ? JSON.stringify(r.details) : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <Pager total={total} limit={LIMIT} offset={offset} onChange={setOffset} />
      </section>
    </>
  );
}
