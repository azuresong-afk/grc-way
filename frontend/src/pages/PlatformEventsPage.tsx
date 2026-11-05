import { RadioTower, RotateCcw } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { EmptyState } from "../components/EmptyState";
import { Pager } from "../components/Pager";
import { ErrorAlert, Loading } from "../components/Status";
import { apiGet, apiPage, apiSend, query } from "../lib/api";
import { formatDateTime, formatNumber } from "../lib/format";

interface PlatformStatus {
  auth_mode: "local" | "platform";
  product_id: string;
  platform_url: string;
  jwks_url: string;
  events_url: string;
  events_secret_set: boolean;
  outbox_enabled: boolean;
  counts: Record<"pending" | "delivered" | "rejected" | "dead", number>;
  shadow_users: number;
  shadow_projects: number;
  last_inbox_at: string | null;
}

interface OutboxEvent {
  id: string;
  type: string;
  project_id: string | null;
  subject: string | null;
  status: "pending" | "delivered" | "rejected" | "dead";
  attempts: number;
  next_at: string;
  last_error: string | null;
  created_at: string;
  delivered_at: string | null;
  data: Record<string, unknown>;
}

const LIMIT = 50;

export const EVENT_TITLES: Record<string, string> = {
  "audit.recorded": "Запись журнала аудита",
  "grc.assessment.updated": "Ход оценки объекта",
  "grc.document.approval_requested": "Документ ждёт утверждения",
};

const STATUS: Record<OutboxEvent["status"], [string, string]> = {
  pending: ["pill-info", "В очереди"],
  delivered: ["pill-ok", "Доставлено"],
  rejected: ["pill-danger", "Отклонено"],
  dead: ["pill-warn", "Не доставлено"],
};

const FILTERS: [string, string][] = [
  ["", "Все"],
  ["pending", "В очереди"],
  ["dead", "Не доставлено"],
  ["rejected", "Отклонено"],
  ["delivered", "Доставлено"],
];

/** Короткое содержание события для таблицы. */
function gist(e: OutboxEvent): string {
  const d = e.data;
  if (e.type === "audit.recorded") {
    const actor = (d.actor as { name?: string } | undefined)?.name;
    return [d.action, d.object, actor].filter(Boolean).join(" · ");
  }
  if (e.type === "grc.assessment.updated") {
    const pct = typeof d.percent === "number" ? `${d.percent} %` : "—";
    return `${String(d.title ?? "")} · ${pct}`;
  }
  return String(d.title ?? e.subject ?? "");
}

export function PlatformEventsPage() {
  const [status, setStatus] = useState<PlatformStatus | null>(null);
  const [items, setItems] = useState<OutboxEvent[] | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setError(null);
    apiGet<PlatformStatus>("/outbox/status")
      .then(setStatus)
      .catch((e: Error) => setError(e.message));
    apiPage<OutboxEvent>(`/outbox${query({ limit: LIMIT, offset, status: filter })}`)
      .then((p) => {
        setItems(p.items);
        setTotal(p.total);
      })
      .catch((e: Error) => setError(e.message));
  }, [offset, filter]);

  useEffect(load, [load]);

  async function retry(id: string) {
    try {
      await apiSend("POST", `/outbox/${encodeURIComponent(id)}/retry`);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось поставить в очередь");
    }
  }

  const c = status?.counts;
  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">Администрирование</div>
          <h1>События платформы</h1>
        </div>
      </div>

      {error && <ErrorAlert message={error} onRetry={load} />}

      {status && (
        <>
          {!status.outbox_enabled && (
            <div className="alert alert-info" role="status">
              Отправка событий выключена: не заданы адрес приёма (PLATFORM_EVENTS_URL или
              PLATFORM_URL в режиме платформы) и секрет PLATFORM_EVENTS_SECRET. «Аттестация»
              работает отдельно, события не копятся.
            </div>
          )}
          <div className="kpi-row">
            <div className="card kpi">
              <span className="kpi-label">Режим входа</span>
              <span className="kpi-value">{status.auth_mode === "platform" ? "Платформа" : "Свой"}</span>
              <span className="kpi-delta">
                {status.auth_mode === "platform"
                  ? `${formatNumber(status.shadow_users)} теневых пользователей · ${formatNumber(status.shadow_projects)} проектов`
                  : "вход по логину и паролю «Аттестации»"}
              </span>
            </div>
            <div className="card kpi">
              <span className="kpi-label">В очереди</span>
              <span className="kpi-value">{formatNumber(c?.pending ?? 0)}</span>
              <span className="kpi-delta">повторы через 1, 5, 15, 60 мин</span>
            </div>
            <div className="card kpi">
              <span className="kpi-label">Не доставлено</span>
              <span className={`kpi-value${(c?.dead ?? 0) + (c?.rejected ?? 0) ? " warn" : ""}`}>
                {formatNumber((c?.dead ?? 0) + (c?.rejected ?? 0))}
              </span>
              <span className="kpi-delta">
                повторы кончились: {formatNumber(c?.dead ?? 0)} · отклонено: {formatNumber(c?.rejected ?? 0)}
              </span>
            </div>
            <div className="card kpi">
              <span className="kpi-label">Доставлено</span>
              <span className="kpi-value">{formatNumber(c?.delivered ?? 0)}</span>
              <span className="kpi-delta">
                входящие: {status.last_inbox_at ? formatDateTime(status.last_inbox_at) : "ещё не было"}
              </span>
            </div>
          </div>
          <section className="card">
            <div className="card-head">
              <h2>Подключение</h2>
            </div>
            <dl className="props card-pad">
              <dt>Продукт</dt>
              <dd className="mono">{status.product_id}</dd>
              <dt>API платформы</dt>
              <dd className="mono">{status.platform_url || "—"}</dd>
              <dt>Открытые ключи</dt>
              <dd className="mono">{status.jwks_url || "—"}</dd>
              <dt>Приём событий</dt>
              <dd className="mono">{status.events_url || "—"}</dd>
              <dt>Секрет подписи</dt>
              <dd>{status.events_secret_set ? "задан" : "не задан"}</dd>
            </dl>
          </section>
        </>
      )}

      <div className="chips" role="group" aria-label="Состояние доставки">
        {FILTERS.map(([value, label]) => (
          <button
            key={value}
            type="button"
            className="chip"
            aria-pressed={filter === value}
            onClick={() => {
              setFilter(value);
              setOffset(0);
            }}
          >
            {label}
          </button>
        ))}
      </div>

      <section className="card">
        {items === null && !error && <Loading />}
        {items?.length === 0 && (
          <EmptyState
            icon={<RadioTower size={21} />}
            title="Событий нет"
            text="Исходящие события появятся, когда включена отправка в «Платформу»."
          />
        )}
        {items && items.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Создано</th>
                  <th>Событие</th>
                  <th>Содержание</th>
                  <th>Доставка</th>
                  <th aria-label="Действия" />
                </tr>
              </thead>
              <tbody>
                {items.map((e) => {
                  const [cls, label] = STATUS[e.status];
                  return (
                    <tr key={e.id}>
                      <td className="nowrap">{formatDateTime(e.created_at)}</td>
                      <td>
                        {EVENT_TITLES[e.type] ?? e.type}
                        <div className="cell-sub mono">{e.subject ?? e.type}</div>
                      </td>
                      <td className="cell-details">{gist(e) || "—"}</td>
                      <td>
                        <span className={`pill ${cls}`}>{label}</span>
                        <div className="cell-sub">
                          {e.status === "delivered" && e.delivered_at
                            ? formatDateTime(e.delivered_at)
                            : e.status === "pending" && e.attempts
                              ? `попытка ${e.attempts + 1} в ${formatDateTime(e.next_at)}`
                              : `попыток: ${e.attempts}`}
                        </div>
                        {e.last_error && <div className="cell-sub">{e.last_error}</div>}
                      </td>
                      <td className="cell-actions">
                        {(e.status === "dead" || e.status === "rejected") && (
                          <button
                            type="button"
                            className="icon-btn"
                            aria-label="Отправить повторно"
                            title="Отправить повторно"
                            onClick={() => retry(e.id)}
                          >
                            <RotateCcw size={15} />
                          </button>
                        )}
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
