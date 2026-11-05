import { AlertTriangle, ExternalLink, ListChecks, RefreshCw, Send } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Drawer } from "../components/Drawer";
import { EmptyState } from "../components/EmptyState";
import { ErrorAlert, Loading } from "../components/Status";
import { ApiError, apiGet, apiSend } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDate } from "../lib/bdu";
import { formatDateTime, formatNumber } from "../lib/format";
import {
  METHODS,
  PRIORITIES,
  PRIORITY_PILL,
  STATE_PILL,
  UPDATE_ORIGINS,
  VERIFY_RESULTS,
  canSend,
  methodShort,
  needsAttention,
  type Method,
  type NcDetail,
  type NcItem,
  type Plan,
  type Priority,
  type SendOut,
  type UpdateOrigin,
} from "../lib/nonconformities";
import type { ObjectFull } from "../lib/objects";
import { decimal, levelClass } from "../lib/vulnCriticality";

function message(e: unknown, fallback: string): string {
  return e instanceof ApiError || e instanceof Error ? e.message : fallback;
}

type Filter = "active" | "measures" | "vulns" | "open" | "attention" | "closed";
const FILTERS: Record<Filter, string> = {
  active: "Все открытые",
  measures: "Меры",
  vulns: "Уязвимости",
  open: "Не отправлены",
  attention: "Требуют внимания",
  closed: "Закрытые",
};

function matches(i: NcItem, f: Filter): boolean {
  if (f === "closed") return i.state === "closed";
  if (i.state === "closed") return false;
  if (f === "measures") return i.kind === "measure";
  if (f === "vulns") return i.kind === "vuln";
  if (f === "open") return i.state === "open";
  if (f === "attention") return needsAttention(i);
  return true;
}

export function PlanTab({ obj, editable }: { obj: ObjectFull; editable: boolean }) {
  const { can } = useAuth();
  const canEdit = editable && can("assessment.edit");
  const [params, setParams] = useSearchParams();
  const [plan, setPlan] = useState<Plan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("active");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const open = params.get("item");

  const load = useCallback(() => {
    setError(null);
    apiGet<Plan>(`/objects/${obj.id}/nonconformities`)
      .then(setPlan)
      .catch((e: Error) => setError(e.message));
  }, [obj.id]);
  useEffect(load, [load]);

  function setOpen(id: string | null) {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (id) next.set("item", id);
        else next.delete("item");
        return next;
      },
      { replace: true },
    );
  }

  const rows = useMemo(() => (plan ? plan.items.filter((i) => matches(i, filter)) : []), [plan, filter]);
  const sendable = rows.filter(canSend);

  async function send(ids: string[]) {
    setBusy(true);
    setNotice(null);
    setError(null);
    try {
      const r = await apiSend<SendOut>("POST", `/objects/${obj.id}/nonconformities/send`, { ids });
      const failed = r.results.filter((x) => !x.ok);
      setNotice(
        `отправлено в «Устранение»: ${r.sent}` +
          (failed.length ? `; не отправлено ${failed.length} — ${failed[0]?.error ?? ""}` : ""),
      );
      setSelected(new Set());
      load();
    } catch (e) {
      setError(message(e, "Не удалось отправить"));
    } finally {
      setBusy(false);
    }
  }

  async function refreshStatuses() {
    setBusy(true);
    setNotice(null);
    setError(null);
    try {
      const r = await apiSend<{ checked: number; changed: number; errors: string[] }>(
        "POST",
        `/objects/${obj.id}/nonconformities/vm-refresh`,
      );
      if (r.errors.length) setError(r.errors[0] ?? "«Устранение» не ответило");
      else setNotice(`проверено заявок: ${r.checked}, изменился статус: ${r.changed}`);
      load();
    } catch (e) {
      setError(message(e, "Не удалось обновить статусы"));
    } finally {
      setBusy(false);
    }
  }

  if (!plan) return error ? <ErrorAlert message={error} /> : <Loading />;
  const c = plan.counts;
  const attention = plan.items.filter(needsAttention).length;

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <>
      {error && <ErrorAlert message={error} />}
      {(c.overdue ?? 0) > 0 && (
        <div className="alert alert-danger" role="status">
          <AlertTriangle size={15} />
          <span className="alert-text">
            Просрочено пунктов плана: {formatNumber(c.overdue ?? 0)}. У уязвимостей прошёл срок по п. 21 Методики, у
            мер — срок, внесённый ответственным.
          </span>
        </div>
      )}
      {(c.decision ?? 0) > 0 && (
        <div className="alert alert-warn" role="status">
          <AlertTriangle size={15} />
          <span className="alert-text">
            Заявки, закрытые «Устранением» без исправления (принят риск, ложное срабатывание или нет исправления у
            производителя): {formatNumber(c.decision ?? 0)}. Нужно решение: компенсирующие меры или повторная отправка.
          </span>
        </div>
      )}
      {!plan.vm.project_id && (
        <div className="alert alert-info">
          <span className="alert-text">
            Проект не связан с «Устранением»: укажите проект в{" "}
            <Link to={`/projects/${obj.project_id}`}>карточке проекта</Link>, чтобы отправлять заявки.
          </span>
        </div>
      )}
      {notice && (
        <div className="alert alert-ok" role="status">
          <span className="alert-text">Готово: {notice}.</span>
        </div>
      )}

      <div className="kpi-row szi-kpis">
        <div className="card kpi">
          <span className="kpi-label">Открытые несоответствия</span>
          <span className={`kpi-value${c.total ? " warn" : " muted"}`}>{formatNumber(c.total ?? 0)}</span>
          <span className="kpi-delta">
            меры {c.measures ?? 0} · уязвимости {c.vulns ?? 0}
          </span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">Не отправлены</span>
          <span className={`kpi-value${c.open ? "" : " muted"}`}>{formatNumber(c.open ?? 0)}</span>
          <span className="kpi-delta">требуют внимания {attention}</span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">В «Устранении»</span>
          <span className={`kpi-value${c.in_vm ? "" : " muted"}`}>{formatNumber(c.in_vm ?? 0)}</span>
          <span className="kpi-delta">
            устранено {c.verified ?? 0} · {plan.vm.events ? "статусы — событиями" : "статусы — опросом"}
          </span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">Просрочены</span>
          <span className={`kpi-value${c.overdue ? " danger" : " muted"}`}>{formatNumber(c.overdue ?? 0)}</span>
          <span className="kpi-delta">
            критический {c.critical ?? 0} · высокий {c.high ?? 0}
          </span>
        </div>
      </div>

      <section className="card">
        <div className="card-head">
          <h2>План устранения</h2>
          <div className="toolbar">
            <select
              className="select toolbar-select"
              aria-label="Показать"
              value={filter}
              onChange={(e) => {
                setFilter(e.target.value as Filter);
                setSelected(new Set());
              }}
            >
              {Object.entries(FILTERS).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </select>
            {canEdit && (
              <>
                <button type="button" className="btn btn-sm" onClick={() => void refreshStatuses()} disabled={busy}>
                  <RefreshCw size={15} /> Обновить статусы
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  disabled={busy || selected.size === 0 || !plan.vm.project_id}
                  onClick={() => void send([...selected])}
                >
                  <Send size={15} /> Отправить в «Устранение»{selected.size ? ` (${selected.size})` : ""}
                </button>
              </>
            )}
          </div>
        </div>
        {plan.items.length === 0 ? (
          <EmptyState
            icon={<ListChecks size={22} />}
            title="Несоответствий нет"
            text="Сюда попадают меры со статусом «Не реализована» и «Частично» и уязвимости из реестра объекта."
          />
        ) : (
          <div className="table-wrap">
            <table className="table plan-table">
              <thead>
                <tr>
                  {canEdit && (
                    <th className="col-check">
                      <input
                        type="checkbox"
                        aria-label="Выбрать все, что можно отправить"
                        checked={sendable.length > 0 && sendable.every((i) => selected.has(i.id))}
                        disabled={sendable.length === 0}
                        onChange={(e) => setSelected(e.target.checked ? new Set(sendable.map((i) => i.id)) : new Set())}
                      />
                    </th>
                  )}
                  <th>Несоответствие</th>
                  <th>Уровень</th>
                  <th>Срок</th>
                  <th>Способ и ответственный</th>
                  <th>«Устранение»</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((i) => (
                  <Row
                    key={i.id}
                    i={i}
                    canEdit={canEdit}
                    checked={selected.has(i.id)}
                    onToggle={() => toggle(i.id)}
                    onOpen={() => setOpen(i.id)}
                  />
                ))}
              </tbody>
            </table>
            {rows.length === 0 && <p className="muted card-pad">Под фильтр ничего не попало.</p>}
          </div>
        )}
      </section>

      {open && (
        <NcDrawer
          id={open}
          plan={plan}
          canEdit={canEdit}
          onClose={() => setOpen(null)}
          onChanged={load}
        />
      )}
    </>
  );
}

function Row({
  i,
  canEdit,
  checked,
  onToggle,
  onOpen,
}: {
  i: NcItem;
  canEdit: boolean;
  checked: boolean;
  onToggle: () => void;
  onOpen: () => void;
}) {
  const closed = i.state === "closed";
  const method = methodShort(i);
  return (
    <tr className={`clickable${closed ? " row-excluded" : ""}`} onClick={onOpen}>
      {canEdit && (
        <td className="col-check" onClick={(e) => e.stopPropagation()}>
          <input
            type="checkbox"
            aria-label={`Выбрать ${i.ref}`}
            checked={checked}
            disabled={!canSend(i)}
            title={i.send_blocker ?? undefined}
            onChange={onToggle}
          />
        </td>
      )}
      <td>
        <button type="button" className="link-btn" onClick={onOpen}>
          <span className={`tag${i.kind === "vuln" && i.ref.startsWith("BDU:") ? " mono" : ""}`}>{i.ref}</span>
        </button>
        <div>{i.title}</div>
        <div className="cell-sub">
          {i.kind === "measure" ? "Мера" : "Уязвимость"} · {i.source_status_title ?? "—"}
          {i.hosts.length > 0 && (
            <>
              {" "}
              · <span className="mono">{i.hosts[0]}</span>
              {i.hosts.length > 1 && ` и ещё ${i.hosts.length - 1}`}
            </>
          )}
        </div>
      </td>
      <td className="nowrap">
        {i.kind === "vuln" ? (
          i.level ? (
            <>
              <span className={levelClass(i.level)}>{i.level_title}</span>
              <div className="cell-sub mono">
                V {decimal(i.v ?? "")}
                {i.certified_szi && " · СЗИ, п. 4"}
              </div>
            </>
          ) : (
            <span className="muted">не оценена</span>
          )
        ) : i.priority ? (
          <span className={PRIORITY_PILL[i.priority]}>{PRIORITIES[i.priority]}</span>
        ) : (
          <span className="muted">—</span>
        )}
      </td>
      <td className="nowrap">
        {i.kind === "vuln" && i.deadline_at ? (
          <span className={i.overdue ? "text-warn" : ""}>{formatDateTime(i.deadline_at)}</span>
        ) : i.due_date ? (
          <span className={i.overdue ? "text-warn" : ""}>{formatDate(i.due_date)}</span>
        ) : (
          <span className="muted">{i.kind === "measure" ? "не указан" : "—"}</span>
        )}
        {i.overdue && <div className="cell-sub text-warn">просрочен</div>}
      </td>
      <td>
        {method ? <div>{method}</div> : i.kind === "vuln" ? <span className="muted">не выбран</span> : null}
        {i.responsible ? (
          <div className="cell-sub">{i.responsible}</div>
        ) : (
          i.kind === "measure" && <span className="muted">ответственный не указан</span>
        )}
      </td>
      <td>
        <span className={`pill ${STATE_PILL[i.state]}`}>{i.state_title}</span>
        {i.vm_ticket_id && (
          <div className="cell-sub">
            №{i.vm_ticket_id} · {i.vm_status_title}
          </div>
        )}
        {i.resend && <div className="cell-sub text-warn">изменилось после отправки</div>}
        {closed && i.close_reason && <div className="cell-sub">{i.close_reason}</div>}
      </td>
    </tr>
  );
}

// ---------- Карточка пункта ----------

function NcDrawer({
  id,
  plan,
  canEdit,
  onClose,
  onChanged,
}: {
  id: string;
  plan: Plan;
  canEdit: boolean;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [d, setD] = useState<NcDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiGet<NcDetail>(`/nonconformities/${id}`).then(setD, (e: Error) => setError(e.message));
  }, [id]);

  async function act(method: string, path: string, body?: unknown) {
    setBusy(true);
    setError(null);
    try {
      setD(await apiSend<NcDetail>(method, path, body));
      onChanged();
    } catch (e) {
      setError(message(e, "Не удалось сохранить"));
    } finally {
      setBusy(false);
    }
  }

  const editable = canEdit && d !== null && d.state !== "closed";
  return (
    <Drawer
      title={d ? `${d.kind === "measure" ? "Мера" : "Уязвимость"} ${d.ref}` : "Несоответствие"}
      subtitle={d?.title}
      onClose={onClose}
      footer={
        d &&
        editable &&
        (canSend(d) || d.send_blocker) && (
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy || !canSend(d) || !plan.vm.project_id}
            title={d.send_blocker ?? undefined}
            onClick={() => void act("POST", `/nonconformities/${d.id}/send`)}
          >
            <Send size={15} /> {d.vm_ticket_id ? "Отправить повторно" : "Отправить в «Устранение»"}
          </button>
        )
      }
    >
      {error && <ErrorAlert message={error} />}
      {!d ? (
        !error && <Loading />
      ) : (
        <>
          {d.warnings.map((w) => (
            <div key={w} className="alert alert-warn">
              <AlertTriangle size={15} />
              <span className="alert-text">{w}</span>
            </div>
          ))}
          {editable && d.send_blocker && (
            <div className="alert alert-info">
              <span className="alert-text">{d.send_blocker}</span>
            </div>
          )}
          <div className="drawer-section">
            <dl className="props">
              <dt>Состояние</dt>
              <dd>
                <span className={`pill ${STATE_PILL[d.state]}`}>{d.state_title}</span>
                {d.close_reason && <div className="cell-sub">{d.close_reason}</div>}
              </dd>
              <dt>{d.kind === "measure" ? "Статус меры" : "Оценка"}</dt>
              <dd>{d.source_status_title ?? "—"}</dd>
              {d.kind === "vuln" && (
                <>
                  <dt>Уровень</dt>
                  <dd>
                    {d.level ? (
                      <>
                        <span className={levelClass(d.level)}>{d.level_title}</span>{" "}
                        <span className="mono">V = {decimal(d.v ?? "")}</span>
                        {d.certified_szi && (
                          <div className="cell-sub">уязвимость в сертифицированном СЗИ — критический уровень (п. 4)</div>
                        )}
                      </>
                    ) : (
                      "не оценена"
                    )}
                  </dd>
                  <dt>Устранить до</dt>
                  <dd className={d.overdue ? "text-warn" : ""}>
                    {d.deadline_at ? (
                      <>
                        {formatDateTime(d.deadline_at)}
                        <div className="cell-sub">
                          п. 21 Методики, от оценки {formatDateTime(d.assessed_at)}
                          {d.overdue && " · просрочен"}
                        </div>
                      </>
                    ) : (
                      "—"
                    )}
                  </dd>
                </>
              )}
              <dt>Хосты</dt>
              <dd className="mono">{d.hosts.length ? d.hosts.join(", ") : "—"}</dd>
              {d.details && (
                <>
                  <dt>Описание</dt>
                  <dd>{d.details}</dd>
                </>
              )}
              <dt>Ссылка</dt>
              <dd>
                <Link
                  to={`/objects/${plan.object_id}?tab=${d.kind === "measure" ? "measures" : "vulns"}`}
                  onClick={onClose}
                >
                  {d.kind === "measure" ? "Открыть на вкладке «Меры»" : "Открыть в реестре уязвимостей"}
                </Link>
              </dd>
            </dl>
          </div>

          <PlanForm key={d.updated_at} d={d} plan={plan} editable={editable} busy={busy} onSave={(b) => void act("PATCH", `/nonconformities/${d.id}`, b)} />

          <div className="drawer-section">
            <h3>«Устранение»</h3>
            {d.vm_ticket_id ? (
              <dl className="props">
                <dt>Заявка</dt>
                <dd>
                  №{d.vm_ticket_id}
                  {d.ticket_url && (
                    <>
                      {" · "}
                      <a href={d.ticket_url} target="_blank" rel="noreferrer">
                        Открыть в «Устранении» <ExternalLink size={12} />
                      </a>
                    </>
                  )}
                </dd>
                <dt>Статус</dt>
                <dd>
                  {d.vm_status_title ?? "—"}
                  <div className="cell-sub">{formatDateTime(d.vm_status_at)}</div>
                </dd>
                <dt>Повторная проверка</dt>
                <dd>
                  {d.vm_verified_result
                    ? `${VERIFY_RESULTS[d.vm_verified_result] ?? d.vm_verified_result}${
                        d.vm_verified_run_id ? `, прогон №${d.vm_verified_run_id}` : ""
                      }`
                    : "ещё не было"}
                </dd>
                <dt>Отправлено</dt>
                <dd>
                  {formatDateTime(d.sent_at)}, {d.sent_by_name ?? "—"}
                </dd>
              </dl>
            ) : (
              <p className="muted">
                Заявки ещё нет.{" "}
                {d.kind === "vuln"
                  ? "В «Устранение» уйдут V, уровень, срок по п. 21, хосты и выбранный способ устранения."
                  : "В «Устранение» уйдут мера, хосты с нарушениями, мероприятие и приоритет."}
              </p>
            )}
          </div>

          <div className="drawer-section">
            <h3>История</h3>
            <ul className="history">
              {d.history.map((e, n) => (
                <li key={n}>
                  <span>{e.text}</span>
                  <span className="cell-sub">
                    {formatDateTime(e.at)}
                    {e.actor_name ? `, ${e.actor_name}` : ""}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        </>
      )}
    </Drawer>
  );
}

interface PatchBody {
  action: string | null;
  responsible: string | null;
  comment: string | null;
  priority?: Priority | null;
  due_date?: string | null;
  method?: Method | null;
  update_origin?: UpdateOrigin | null;
  update_tested?: boolean | null;
  compensating?: string[];
}

function PlanForm({
  d,
  plan,
  editable,
  busy,
  onSave,
}: {
  d: NcDetail;
  plan: Plan;
  editable: boolean;
  busy: boolean;
  onSave: (b: PatchBody) => void;
}) {
  const [action, setAction] = useState(d.action ?? "");
  const [responsible, setResponsible] = useState(d.responsible ?? "");
  const [comment, setComment] = useState(d.comment ?? "");
  const [priority, setPriority] = useState<Priority | "">(d.priority ?? "");
  const [due, setDue] = useState(d.due_date ?? "");
  const [method, setMethod] = useState<Method | "">(d.method ?? "");
  const [origin, setOrigin] = useState<UpdateOrigin | "">(d.update_origin ?? "");
  const [tested, setTested] = useState(Boolean(d.update_tested));
  const [codes, setCodes] = useState<string[]>(d.compensating);

  function submit(e: FormEvent) {
    e.preventDefault();
    const body: PatchBody = {
      action: action.trim() || null,
      responsible: responsible.trim() || null,
      comment: comment.trim() || null,
    };
    if (d.kind === "measure") {
      body.priority = priority || null;
      body.due_date = due || null;
    } else {
      body.method = method || null;
      body.update_origin = method === "update" ? origin || null : null;
      body.update_tested = method === "update" ? tested : null;
      body.compensating = method === "compensating" ? codes : [];
    }
    onSave(body);
  }

  const needsTesting = origin === "foreign" || origin === "opensource";
  return (
    <form className="drawer-section form-stack drawer-form" onSubmit={submit}>
      <h3>Мероприятие</h3>
      {d.kind === "vuln" && (
        <div className="field">
          <span>Способ устранения (п. 22 Методики)</span>
          <div className="seg" role="radiogroup" aria-label="Способ устранения">
            {(["", "update", "compensating"] as const).map((k) => (
              <button
                key={k || "none"}
                type="button"
                role="radio"
                aria-checked={method === k}
                className="seg-btn"
                disabled={!editable}
                onClick={() => setMethod(k)}
              >
                {k ? METHODS[k] : "Не выбран"}
              </button>
            ))}
          </div>
        </div>
      )}
      {d.kind === "vuln" && method === "update" && (
        <>
          <label className="field">
            <span>Чьё ПО обновляется</span>
            <select
              className="select"
              value={origin}
              disabled={!editable}
              onChange={(e) => setOrigin(e.target.value as UpdateOrigin | "")}
            >
              <option value="">не указано</option>
              {Object.entries(UPDATE_ORIGINS).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </select>
          </label>
          {needsTesting && (
            <label className="check">
              <input type="checkbox" checked={tested} disabled={!editable} onChange={(e) => setTested(e.target.checked)} />
              <span>
                <b>Обновление протестировано</b>
                <small>по Методике тестирования обновлений безопасности (ФСТЭК России, 2022) — п. 23</small>
              </span>
            </label>
          )}
        </>
      )}
      {d.kind === "vuln" && method === "compensating" && (
        <div className="field" role="group" aria-label="Компенсирующие меры">
          <span>Компенсирующие меры (перечень п. 25)</span>
          {plan.compensating_measures.map((cm) => (
            <label key={cm.code} className="check">
              <input
                type="checkbox"
                checked={codes.includes(cm.code)}
                disabled={!editable}
                onChange={(e) =>
                  setCodes((prev) => (e.target.checked ? [...prev, cm.code] : prev.filter((x) => x !== cm.code)))
                }
              />
              <span>
                <b className="mono">{cm.code}</b> <small>{cm.title}</small>
              </span>
            </label>
          ))}
        </div>
      )}
      <label className="field">
        <span>Что сделать</span>
        <textarea
          className="input"
          rows={2}
          value={action}
          placeholder={d.default_action}
          disabled={!editable}
          maxLength={2000}
          onChange={(e) => setAction(e.target.value)}
        />
      </label>
      <label className="field">
        <span>Ответственный</span>
        <input
          className="input"
          value={responsible}
          disabled={!editable}
          maxLength={300}
          placeholder="ФИО, должность"
          onChange={(e) => setResponsible(e.target.value)}
        />
      </label>
      {d.kind === "measure" && (
        <div className="form-row">
          <label className="field">
            <span>Приоритет</span>
            <select
              className="select"
              value={priority}
              disabled={!editable}
              onChange={(e) => setPriority(e.target.value as Priority | "")}
            >
              <option value="">не указан</option>
              {Object.entries(PRIORITIES).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Срок (необязательно)</span>
            <input className="input" type="date" value={due} disabled={!editable} onChange={(e) => setDue(e.target.value)} />
          </label>
        </div>
      )}
      <label className="field">
        <span>Комментарий</span>
        <textarea
          className="input"
          rows={2}
          value={comment}
          disabled={!editable}
          maxLength={2000}
          onChange={(e) => setComment(e.target.value)}
        />
      </label>
      {editable && (
        <div>
          <button type="submit" className="btn" disabled={busy}>
            Сохранить
          </button>
        </div>
      )}
    </form>
  );
}

/** Блок «Несоответствие» в шторке меры: состояние в плане и «Отправить в «Устранение»». */
export function MeasureRemediation({
  measureId,
  objectId,
  canAssess,
}: {
  measureId: string;
  objectId: string;
  canAssess: boolean;
}) {
  const [nc, setNc] = useState<NcItem | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiGet<NcItem | null>(`/object-measures/${measureId}/nonconformity`).then(setNc, () => setNc(null));
  }, [measureId]);

  if (!nc || nc.state === "closed") return null;

  async function send() {
    if (!nc) return;
    setBusy(true);
    setError(null);
    try {
      setNc(await apiSend<NcDetail>("POST", `/nonconformities/${nc.id}/send`));
    } catch (e) {
      setError(message(e, "Не удалось отправить"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="drawer-section">
      <h3>Несоответствие</h3>
      {error && <ErrorAlert message={error} />}
      <p>
        <span className={`pill ${STATE_PILL[nc.state]}`}>{nc.state_title}</span>
        {nc.vm_ticket_id && (
          <span className="muted">
            {" "}
            заявка №{nc.vm_ticket_id} · {nc.vm_status_title}
          </span>
        )}
      </p>
      {nc.send_blocker && <p className="muted">{nc.send_blocker}</p>}
      <div className="toolbar">
        {canAssess && canSend(nc) && (
          <button type="button" className="btn btn-sm btn-primary" disabled={busy} onClick={() => void send()}>
            <Send size={15} /> {nc.vm_ticket_id ? "Отправить повторно" : "Отправить в «Устранение»"}
          </button>
        )}
        <Link className="btn btn-sm" to={`/objects/${objectId}?tab=plan&item=${nc.id}`}>
          Открыть в плане
        </Link>
      </div>
    </div>
  );
}
