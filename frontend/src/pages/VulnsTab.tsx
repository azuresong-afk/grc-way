import { AlertTriangle, Bug, Plus, RefreshCw, Trash2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Drawer } from "../components/Drawer";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { ApiError, apiGet, apiSend } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDateTime, formatNumber } from "../lib/format";
import type { ObjectFull } from "../lib/objects";
import { decimal, deadlineText, levelClass, sourceLine, type Methodology } from "../lib/vulnCriticality";
import {
  BASIS,
  CVSS_SOURCES,
  CVSS_VERSIONS,
  MANUAL_SOURCES,
  STATE_PILL,
  parseAddresses,
  type AssessedOutcome,
  type Assessment,
  type Register,
  type VulnDetail,
  type VulnRow,
} from "../lib/vulnRegister";

const METHODOLOGY = "fstec-2025";

function message(e: unknown, fallback: string): string {
  return e instanceof ApiError || e instanceof Error ? e.message : fallback;
}

type Filter = "all" | "attention" | "current" | "not_detected";
const FILTERS: Record<Filter, string> = {
  all: "Все",
  attention: "Требуют внимания",
  current: "Оценка актуальна",
  not_detected: "Не обнаружены",
};

function matches(r: VulnRow, f: Filter): boolean {
  if (f === "all") return true;
  if (f === "attention") return ["stale", "not_assessed", "incomplete"].includes(r.state);
  return r.state === f;
}

export function VulnsTab({ obj, editable }: { obj: ObjectFull; editable: boolean }) {
  const { can } = useAuth();
  const canEdit = editable && can("assessment.edit");
  const [data, setData] = useState<Register | null>(null);
  const [methodology, setMethodology] = useState<Methodology | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [open, setOpen] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(() => {
    setError(null);
    apiGet<Register>(`/objects/${obj.id}/vulns`)
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [obj.id]);
  useEffect(load, [load]);
  useEffect(() => {
    apiGet<Methodology>(`/refs/vuln-criticality/${METHODOLOGY}`).then(setMethodology, () => setMethodology(null));
  }, []);

  async function refresh() {
    setBusy(true);
    setNotice(null);
    try {
      const r = await apiSend<{ snapshot: number | null; created: number; assessed: number; stale_incomplete: number }>(
        "POST",
        `/objects/${obj.id}/vulns/refresh`,
      );
      const parts = [`пересчитано оценок: ${r.assessed}`];
      if (r.created) parts.push(`новых уязвимостей: ${r.created}`);
      if (r.stale_incomplete) parts.push(`не хватает данных для пересчёта: ${r.stale_incomplete}`);
      setNotice(parts.join(", "));
      load();
    } catch (e) {
      setError(message(e, "Не удалось пересчитать"));
    } finally {
      setBusy(false);
    }
  }

  const rows = useMemo(() => (data ? data.items.filter((r) => matches(r, filter)) : []), [data, filter]);

  if (error && !data) return <ErrorAlert message={error} onRetry={load} />;
  if (!data) return <Loading />;
  const c = data.counts;
  const attention = c.stale + c.not_assessed + c.incomplete;

  return (
    <>
      {error && <ErrorAlert message={error} />}
      {c.overdue > 0 && (
        <div className="alert alert-danger" role="status">
          <AlertTriangle size={15} />
          <span className="alert-text">
            У {formatNumber(c.overdue)} уязвимостей прошёл рекомендуемый срок устранения (п. 21 Методики).
          </span>
        </div>
      )}
      {c.stale > 0 && (
        <div className="alert alert-warn" role="status">
          <AlertTriangle size={15} />
          <span className="alert-text">
            {formatNumber(c.stale)} оценок устарели: с момента расчёта изменились исходные данные. Пересчёт добавит
            новую оценку, прежняя останется в истории.
          </span>
        </div>
      )}
      {!data.snapshot && (
        <div className="alert alert-info">
          <span className="alert-text">
            Снимков «Сканера» ещё нет: уязвимости попадут в реестр после импорта прогона на вкладке «Меры». Найденное
            при тестировании на проникновение или учениях можно внести вручную.
          </span>
        </div>
      )}
      {data.snapshot && !data.snapshot.findings_loaded && (
        <div className="alert alert-info">
          <span className="alert-text">
            Текущий снимок №{data.snapshot.number} сделан без находок «Сканера». Импортируйте прогон повторно.
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
          <span className="kpi-label">В реестре</span>
          <span className={`kpi-value${c.total ? "" : " muted"}`}>{formatNumber(c.total)}</span>
          <span className="kpi-delta">
            {data.snapshot ? `снимок №${data.snapshot.number}` : "снимков нет"} · Методика 2025, ред.{" "}
            {data.methodology.revision}
          </span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">Критический / высокий</span>
          <span className={`kpi-value${c.critical ? " danger" : c.high ? " warn" : " muted"}`}>
            {formatNumber(c.critical)} / {formatNumber(c.high)}
          </span>
          <span className="kpi-delta">
            средний {formatNumber(c.medium)}, низкий {formatNumber(c.low)}
          </span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">Требуют внимания</span>
          <span className={`kpi-value${attention ? " warn" : " muted"}`}>{formatNumber(attention)}</span>
          <span className="kpi-delta">
            устарели {c.stale}, не оценены {c.not_assessed}, нет данных {c.incomplete}
          </span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">Просрочены</span>
          <span className={`kpi-value${c.overdue ? " danger" : " muted"}`}>{formatNumber(c.overdue)}</span>
          <span className="kpi-delta">срок по п. 21</span>
        </div>
      </div>

      <section className="card">
        <div className="card-head">
          <h2>Реестр уязвимостей</h2>
          <div className="toolbar">
            <select
              className="select toolbar-select"
              aria-label="Показать"
              value={filter}
              onChange={(e) => setFilter(e.target.value as Filter)}
            >
              {Object.entries(FILTERS).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </select>
            {canEdit && (
              <>
                <button type="button" className="btn btn-sm" onClick={() => void refresh()} disabled={busy}>
                  <RefreshCw size={15} /> Пересчитать
                </button>
                <button type="button" className="btn btn-sm btn-primary" onClick={() => setAdding(true)}>
                  <Plus size={15} /> Внести вручную
                </button>
              </>
            )}
          </div>
        </div>
        {data.items.length === 0 ? (
          <EmptyState
            icon={<Bug size={22} />}
            title="Уязвимостей в реестре нет"
            text="Сюда попадают находки «Сканера» с идентификаторами БДУ из текущего снимка и уязвимости, внесённые по результатам контроля защищённости."
          />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Уязвимость</th>
                  <th>Хосты</th>
                  <th className="num">V</th>
                  <th>Уровень</th>
                  <th>Срок устранения</th>
                  <th>Состояние</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <Row key={r.id} r={r} onOpen={() => setOpen(r.id)} />
                ))}
              </tbody>
            </table>
            {rows.length === 0 && <p className="muted card-pad">Под фильтр ничего не попало.</p>}
          </div>
        )}
      </section>

      {open && (
        <VulnDrawer
          id={open}
          methodology={methodology}
          canEdit={canEdit}
          onClose={() => setOpen(null)}
          onChanged={load}
        />
      )}
      {adding && (
        <ManualDialog
          objectId={obj.id}
          onClose={() => setAdding(false)}
          onCreated={(id) => {
            setAdding(false);
            load();
            setOpen(id);
          }}
        />
      )}
    </>
  );
}

function Row({ r, onOpen }: { r: VulnRow; onOpen: () => void }) {
  const a = r.current;
  const gone = r.state === "not_detected";
  return (
    <tr className={`clickable${gone ? " row-excluded" : ""}`} onClick={onOpen}>
      <td>
        <button type="button" className="link-btn" onClick={onOpen}>
          {r.bdu_id ? <span className="tag mono">{r.bdu_id}</span> : <span className="tag">без БДУ</span>}
        </button>
        <div>{r.title}</div>
        <div className="cell-sub">
          {r.origin === "manual" ? r.manual_source_title : "«Сканер»"}
          {r.cve_ids.length > 0 && <span className="mono"> · {r.cve_ids.slice(0, 3).join(", ")}</span>}
        </div>
      </td>
      <td className="nowrap">
        {r.hosts.length ? (
          <>
            <span className="mono">{r.hosts[0]}</span>
            {r.hosts.length > 1 && <div className="cell-sub">и ещё {r.hosts.length - 1}</div>}
          </>
        ) : (
          <span className="muted">
            нет{r.last_seen_snapshot ? ` (был в снимке №${r.last_seen_snapshot})` : ""}
          </span>
        )}
      </td>
      <td className="num nowrap mono">{a ? decimal(a.v) : <span className="muted">—</span>}</td>
      <td className="nowrap">
        {a ? <span className={levelClass(a.level)}>{a.level_title}</span> : <span className="muted">—</span>}
      </td>
      <td className="nowrap">
        {a ? (
          <>
            <span className={a.overdue && !gone ? "text-warn" : ""}>{formatDateTime(a.deadline_at)}</span>
            {a.overdue && !gone && <div className="cell-sub text-warn">просрочен</div>}
          </>
        ) : (
          <span className="muted">—</span>
        )}
      </td>
      <td>
        <span className={`pill ${STATE_PILL[r.state] || "pill-muted"}`}>{r.state_title}</span>
        {r.state === "stale" && r.preview && (
          <div className="cell-sub">
            сейчас V {decimal(r.preview.v)} · {r.preview.level_title.toLowerCase()}
          </div>
        )}
        {r.state === "incomplete" && (
          <div className="cell-sub">нужно: {r.missing.map((m) => m.indicator).join(", ")}</div>
        )}
      </td>
    </tr>
  );
}

// ---------- Карточка ----------

function VulnDrawer({
  id,
  methodology,
  canEdit,
  onClose,
  onChanged,
}: {
  id: string;
  methodology: Methodology | null;
  canEdit: boolean;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [d, setD] = useState<VulnDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    apiGet<VulnDetail>(`/object-vulns/${id}`).then(setD, (e: Error) => setError(e.message));
  }, [id]);
  useEffect(load, [load]);

  async function act(method: string, path: string, body?: unknown) {
    setBusy(true);
    setError(null);
    try {
      if (method === "DELETE") {
        await apiSend(method, path);
        onChanged();
        onClose();
        return;
      }
      setD(await apiSend<VulnDetail>(method, path, body));
      onChanged();
    } catch (e) {
      setError(message(e, "Не удалось сохранить"));
    } finally {
      setBusy(false);
    }
  }

  const current = d?.history[0] ?? null;
  return (
    <Drawer
      title={d ? (d.bdu_id ?? "Уязвимость без идентификатора БДУ") : "Уязвимость"}
      subtitle={d?.title}
      onClose={onClose}
      footer={
        d &&
        canEdit && (
          <>
            {d.origin === "manual" && d.assessments === 0 && (
              <button
                type="button"
                className="btn btn-ghost"
                disabled={busy}
                onClick={() => void act("DELETE", `/object-vulns/${d.id}`)}
              >
                <Trash2 size={15} /> Удалить
              </button>
            )}
            {d.state === "stale" && (
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy}
                onClick={() => void act("POST", `/object-vulns/${d.id}/assess`)}
              >
                <RefreshCw size={15} /> Пересчитать
              </button>
            )}
          </>
        )
      }
    >
      {error && <ErrorAlert message={error} />}
      {!d ? (
        !error && <Loading />
      ) : (
        <>
          <div className="drawer-section">
            <dl className="props">
              <dt>Состояние</dt>
              <dd>
                <span className={`pill ${STATE_PILL[d.state] || "pill-muted"}`}>{d.state_title}</span>
              </dd>
              <dt>Уязвимые хосты</dt>
              <dd className="mono">{d.hosts.length ? d.hosts.join(", ") : <span className="muted">нет</span>}</dd>
              <dt>Источник</dt>
              <dd>
                {d.scanner_hosts.length > 0 && <div>«Сканер»: {d.scanner_hosts.length} хост(ов)</div>}
                {d.manual_hosts.length > 0 && (
                  <div>
                    {d.manual_source_title}: {d.manual_hosts.join(", ")}
                  </div>
                )}
                {!d.scanner_hosts.length && !d.manual_hosts.length && (
                  <span className="muted">
                    в текущем снимке не найдена
                    {d.last_seen_snapshot ? `, последний раз — снимок №${d.last_seen_snapshot}` : ""}
                  </span>
                )}
              </dd>
            </dl>
            {d.missing.length > 0 && d.state !== "not_detected" && (
              <div className="alert alert-warn">
                <span className="alert-text">
                  Для расчёта не хватает данных:
                  <ul>
                    {d.missing.map((m) => (
                      <li key={m.indicator + m.text}>
                        {m.text}
                        {m.addresses.length > 0 && <span className="mono"> — {m.addresses.slice(0, 8).join(", ")}</span>}
                      </li>
                    ))}
                  </ul>
                </span>
              </div>
            )}
            {d.stale_reasons.length > 0 && (
              <div className="alert alert-warn">
                <span className="alert-text">
                  Оценка №{current?.number} устарела: {d.stale_reasons.join("; ")}.
                  {d.preview && ` Сейчас V = ${decimal(d.preview.v)}, уровень «${d.preview.level_title}».`}
                </span>
              </div>
            )}
            {d.proposal.notes.map((n) => (
              <div key={n} className="alert alert-info">
                <span className="alert-text">{n}</span>
              </div>
            ))}
          </div>

          {current && (
            <div className="drawer-section">
              <h3>
                Оценка №{current.number} — как посчитано
              </h3>
              <AssessmentView a={current} />
            </div>
          )}

          {canEdit && methodology && (
            <ChoicesForm d={d} methodology={methodology} busy={busy} onSave={(b) => void act("PATCH", `/object-vulns/${d.id}`, b)} />
          )}

          {d.findings.length > 0 && (
            <div className="drawer-section">
              <h3>Находки «Сканера» (снимок №{d.last_seen_snapshot})</h3>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Хост</th>
                      <th>Находка</th>
                      <th className="num">CVSS</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.findings.map((f) => (
                      <tr key={f.dedup_key}>
                        <td className="mono nowrap">
                          {f.host}
                          {f.port ? `:${f.port}` : ""}
                        </td>
                        <td>
                          {f.title}
                          {f.software && (
                            <div className="cell-sub">
                              {f.software} {f.software_version}
                            </div>
                          )}
                        </td>
                        <td className="num mono">{f.cvss ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {d.bdu && (
            <div className="drawer-section">
              <h3>Сведения БДУ</h3>
              <dl className="props">
                <dt>Уровень опасности</dt>
                <dd>{d.bdu.severity ?? "—"}</dd>
                <dt>CVSS 3.x</dt>
                <dd className="mono">
                  {d.bdu.cvss3_score !== null ? `${decimal(d.bdu.cvss3_score)} (CVSS ${d.bdu.cvss3_version})` : "нет"}
                  {d.bdu.cvss3_vector && <div className="cell-sub">{d.bdu.cvss3_vector}</div>}
                </dd>
                <dt>Эксплуатация в атаках</dt>
                <dd>{d.bdu.in_wild_raw ?? "—"}</dd>
                <dt>Наличие эксплойта</dt>
                <dd>{d.bdu.exploit_raw ?? "—"}</dd>
                {d.bdu.criticality_changed_at && (
                  <>
                    <dt>Сведения изменились</dt>
                    <dd>{formatDateTime(d.bdu.criticality_changed_at)}</dd>
                  </>
                )}
              </dl>
              <Link to={`/refs/bdu?q=${encodeURIComponent(d.bdu.bdu_id)}`}>Открыть в справочнике БДУ</Link>
            </div>
          )}
          {d.bdu_id && !d.bdu && (
            <div className="drawer-section">
              <div className="alert alert-info">
                <span className="alert-text">
                  {d.bdu_id} нет в загруженной выгрузке БДУ: CVSS и сведения об эксплуатации выбирает специалист.{" "}
                  <Link to="/refs/bdu">Справочники → БДУ</Link>
                </span>
              </div>
            </div>
          )}

          {d.history.length > 0 && (
            <div className="drawer-section">
              <h3>История оценок</h3>
              <ol className="vuln-history">
                {d.history.map((a) => (
                  <HistoryItem key={a.id} a={a} />
                ))}
              </ol>
            </div>
          )}
        </>
      )}
    </Drawer>
  );
}

function HistoryItem({ a }: { a: Assessment }) {
  return (
    <li>
      <details>
        <summary>
          <b>№{a.number}</b> · {formatDateTime(a.assessed_at)} · V {decimal(a.v)}{" "}
          <span className={levelClass(a.level)}>{a.level_title}</span>
          <div className="cell-sub">
            {a.trigger_title}
            {a.assessed_by_name ? `, ${a.assessed_by_name}` : ""}
            {a.reasons.length > 0 && ` — ${a.reasons.join("; ")}`}
          </div>
        </summary>
        <AssessmentView a={a} />
      </details>
    </li>
  );
}

function AssessmentView({ a }: { a: Assessment }) {
  return (
    <>
      <div className="vuln-kpis">
        <div className="kpi">
          <div className="kpi-label">V</div>
          <div className="kpi-value">{decimal(a.v)}</div>
          <div className="cell-sub">точно {decimal(a.outcome.v_exact)}</div>
        </div>
        <div className="kpi">
          <div className="kpi-label">Уровень</div>
          <div className="kpi-value">
            <span className={levelClass(a.level)}>{a.level_title}</span>
          </div>
          <div className="cell-sub">{a.outcome.level.condition}</div>
        </div>
        <div className="kpi">
          <div className="kpi-label">Устранить до</div>
          <div className={`kpi-value${a.overdue ? " danger" : ""}`}>{formatDateTime(a.deadline_at)}</div>
          <div className="cell-sub">
            {deadlineText(a.outcome.level.deadline)} (п. 21)
            {a.deadline_from !== a.number && ` — срок оценки №${a.deadline_from}, уровень не менялся`}
          </div>
        </div>
      </div>
      <OutcomeTrace outcome={a.outcome} />
      <p className="cell-sub">
        Методика 2025, редакция {a.methodology_revision}
        {a.snapshot_number ? ` · снимок «Сканера» №${a.snapshot_number}` : ""} · хосты: {a.hosts.join(", ")}
      </p>
    </>
  );
}

function OutcomeTrace({ outcome }: { outcome: AssessedOutcome }) {
  const g = outcome.groups;
  return (
    <>
      <p className="mono vc-formula">
        V = {decimal(outcome.cvss)} × {decimal(g.infr)} × ({decimal(g.at)} + {decimal(g.imp)}) ≈ {decimal(outcome.v)}
      </p>
      {outcome.level_by_v && (
        <div className="alert alert-warn">
          <span className="alert-text">
            По значению V уровень был бы другим; критический присвоен по п. 4 — уязвимость в сертифицированном СЗИ.
          </span>
        </div>
      )}
      <div className="table-wrap">
        <table className="table vuln-trace">
          <thead>
            <tr>
              <th>Показатель</th>
              <th>Значение и откуда взято</th>
              <th className="num">Вес × оценка</th>
            </tr>
          </thead>
          <tbody>
            {outcome.trace.map((t) => (
              <tr key={t.indicator}>
                <td>
                  {t.indicator === "cvss" ? "I_cvss" : t.indicator}
                  <div className="cell-sub">{sourceLine(t.source)}</div>
                </td>
                <td>
                  {t.value ? (
                    <>
                      <span className="tag">{t.value}</span>{" "}
                      <span className="cell-sub vuln-value-title">{t.value_title}</span>
                      {t.rule && (
                        <div className="cell-sub">
                          {t.rule} из {t.chosen?.map((c) => `${c.code} (${decimal(c.score)})`).join(", ")}
                        </div>
                      )}
                    </>
                  ) : (
                    <span className="cell-sub">{t.title}</span>
                  )}
                  {t.fallback && <div className="cell-sub text-warn">версия CVSS выбрана специалистом (п. 13)</div>}
                  {(t.basis_kind || t.basis) && (
                    <div className="vuln-basis">
                      {t.basis_kind && <span className="pill pill-muted">{BASIS[t.basis_kind]}</span>} {t.basis}
                    </div>
                  )}
                </td>
                <td className="num nowrap mono">
                  {t.weight ? `${decimal(t.weight)} × ${decimal(t.score)} = ${decimal(t.product)}` : decimal(t.score)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

// ---------- Выбор специалиста ----------

interface ChoicesBody {
  cvss?: { version: string; score: number; source: string; vector?: string | null; note?: string | null };
  clear_cvss?: boolean;
  e: string[];
  h: string[];
  certified_szi: boolean;
  manual_hosts: string[];
  manual_source?: string;
  comment: string;
}

function ChoicesForm({
  d,
  methodology,
  busy,
  onSave,
}: {
  d: VulnDetail;
  methodology: Methodology;
  busy: boolean;
  onSave: (b: ChoicesBody) => void;
}) {
  const def = methodology.definition;
  const eInd = def.indicators.find((i) => (i as { bdu?: string }).bdu === "exploitation");
  const hInd = def.indicators.find((i) => i.group === "imp");
  const cvss = d.proposal.cvss;
  const needCvss = cvss.source !== "bdu" || cvss.fallback;
  const [cvssVersion, setCvssVersion] = useState(d.choices.cvss?.version ?? cvss.options[0]?.version ?? "3.1");
  const [cvssScore, setCvssScore] = useState(String(d.choices.cvss?.score ?? cvss.options[0]?.score ?? ""));
  const [cvssSource, setCvssSource] = useState(d.choices.cvss?.source ?? cvss.options[0]?.source ?? "manual");
  const [cvssNote, setCvssNote] = useState(d.choices.cvss?.note ?? "");
  const [e, setE] = useState<string[]>(d.choices.e);
  const [h, setH] = useState<string[]>(d.choices.h);
  const [szi, setSzi] = useState(d.choices.certified_szi);
  const [hosts, setHosts] = useState(d.manual_hosts.join(", "));
  const [source, setSource] = useState(d.manual_source ?? "pentest");
  const [comment, setComment] = useState(d.comment ?? "");
  const bduE = d.proposal.exploitation.bdu;

  function toggle(list: string[], set: (v: string[]) => void, code: string) {
    set(list.includes(code) ? list.filter((c) => c !== code) : [...list, code]);
  }

  function submit(ev: FormEvent) {
    ev.preventDefault();
    const body: ChoicesBody = {
      e,
      h,
      certified_szi: szi,
      manual_hosts: parseAddresses(hosts),
      comment,
    };
    if (body.manual_hosts.length) body.manual_source = source;
    if (needCvss && cvssScore.trim()) {
      body.cvss = {
        version: cvssVersion,
        score: Number(cvssScore.replace(",", ".")),
        source: cvssSource,
        note: cvssNote.trim() || null,
      };
    }
    onSave(body);
  }

  return (
    <form className="drawer-section drawer-form form-stack" onSubmit={submit} aria-label="Выбор специалиста">
      <h3>Выбор специалиста</h3>
      {needCvss && (
        <fieldset className="field">
          <legend className="field-legend">
            I_cvss: в БДУ нет оценки CVSS {cvss.target_version} — выберите версию и оценку (п. 13)
          </legend>
          {cvss.options.length > 0 && (
            <div className="chips">
              {cvss.options.map((o) => (
                <button
                  key={o.title}
                  type="button"
                  className="chip"
                  aria-pressed={cvssScore === o.score && cvssSource === o.source}
                  onClick={() => {
                    setCvssScore(o.score);
                    setCvssSource(o.source);
                    if (o.version) setCvssVersion(o.version);
                  }}
                >
                  {o.title}: {decimal(o.score)}
                </button>
              ))}
            </div>
          )}
          <div className="form-row">
            <label className="field">
              <span>Версия CVSS</span>
              <select className="select" value={cvssVersion} onChange={(ev) => setCvssVersion(ev.target.value)}>
                {CVSS_VERSIONS.map((v) => (
                  <option key={v} value={v}>
                    CVSS {v}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Базовая оценка</span>
              <input
                className="input mono"
                inputMode="decimal"
                value={cvssScore}
                onChange={(ev) => setCvssScore(ev.target.value)}
              />
            </label>
            <label className="field">
              <span>Источник</span>
              <select className="select" value={cvssSource} onChange={(ev) => setCvssSource(ev.target.value)}>
                {Object.entries(CVSS_SOURCES).map(([k, v]) => (
                  <option key={k} value={k}>
                    {v}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <label className="field">
            <span>Обоснование</span>
            <input className="input" value={cvssNote} maxLength={1000} onChange={(ev) => setCvssNote(ev.target.value)} />
          </label>
        </fieldset>
      )}
      {eInd && (
        <fieldset className="field">
          <legend className="field-legend">
            E — эксплуатация (п. 16): {bduE ? `по БДУ ${bduE}; добавьте, если знаете больше — берётся наибольшее` : "в БДУ сведений нет, выберите"}
          </legend>
          <div className="chips">
            {eInd.values.map((v) => (
              <button
                key={v.code}
                type="button"
                className="chip"
                title={v.title}
                aria-pressed={e.includes(v.code) || v.code === bduE}
                disabled={v.code === bduE}
                onClick={() => toggle(e, setE, v.code)}
              >
                {v.code} · {v.title}
              </button>
            ))}
          </div>
        </fieldset>
      )}
      {hInd && (
        <fieldset className="field">
          <legend className="field-legend">H — последствия эксплуатации (п. 17), берётся наибольшее</legend>
          <div className="chips">
            {hInd.values.map((v) => (
              <button
                key={v.code}
                type="button"
                className="chip"
                aria-pressed={h.includes(v.code)}
                onClick={() => toggle(h, setH, v.code)}
              >
                {v.code} · {v.title} ({decimal(v.score)})
              </button>
            ))}
          </div>
        </fieldset>
      )}
      <label className="check">
        <input type="checkbox" checked={szi} onChange={(ev) => setSzi(ev.target.checked)} />
        <span>
          <b>Уязвимость в сертифицированном СЗИ</b>
          <small>П. 4: такой уязвимости присваивается критический уровень при любом V.</small>
        </span>
      </label>
      <div className="form-row">
        <label className="field">
          <span>Хосты по результатам контроля защищённости</span>
          <input
            className="input mono"
            value={hosts}
            placeholder="10.10.1.10, 10.10.1.11"
            onChange={(ev) => setHosts(ev.target.value)}
          />
          <small>Дополнительно к найденным «Сканером». Только хосты из состава объекта.</small>
        </label>
        <label className="field">
          <span>Источник сведений (п. 8 «г»)</span>
          <select className="select" value={source} onChange={(ev) => setSource(ev.target.value)}>
            {Object.entries(MANUAL_SOURCES).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label className="field">
        <span>Комментарий</span>
        <input className="input" value={comment} maxLength={2000} onChange={(ev) => setComment(ev.target.value)} />
      </label>
      <div>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          Сохранить и рассчитать
        </button>
        <small className="muted"> Если данных хватает и что-то изменилось, появится новая оценка.</small>
      </div>
    </form>
  );
}

// ---------- Ручной ввод ----------

function ManualDialog({
  objectId,
  onClose,
  onCreated,
}: {
  objectId: string;
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const [bdu, setBdu] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [source, setSource] = useState("pentest");
  const [hosts, setHosts] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const addresses = parseAddresses(hosts);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const d = await apiSend<VulnDetail>("POST", `/objects/${objectId}/vulns`, {
        bdu_id: bdu.trim() || null,
        title: title.trim() || null,
        description: description.trim() || null,
        manual_source: source,
        manual_hosts: addresses,
      });
      onCreated(d.id);
    } catch (e2) {
      setError(message(e2, "Не удалось сохранить"));
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Внести уязвимость"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="submit"
            form="vuln-form"
            className="btn btn-primary"
            disabled={busy || !addresses.length || (!bdu.trim() && !title.trim())}
          >
            Внести
          </button>
        </>
      }
    >
      <form id="vuln-form" className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <div className="form-row">
          <label className="field">
            <span>Идентификатор БДУ</span>
            <input
              className="input mono"
              value={bdu}
              placeholder="BDU:2025-01611"
              maxLength={32}
              onChange={(e) => setBdu(e.target.value)}
            />
            <small>Пусто — уязвимость без идентификатора (например, найдена при пентесте).</small>
          </label>
          <label className="field">
            <span>Источник сведений (п. 8 «г»)</span>
            <select className="select" value={source} onChange={(e) => setSource(e.target.value)}>
              {Object.entries(MANUAL_SOURCES).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label className="field">
          <span>Наименование</span>
          <input
            className="input"
            value={title}
            maxLength={2000}
            placeholder={bdu.trim() ? "из БДУ, если пусто" : ""}
            onChange={(e) => setTitle(e.target.value)}
          />
        </label>
        <label className="field">
          <span>Описание</span>
          <textarea className="input" rows={3} value={description} onChange={(e) => setDescription(e.target.value)} />
        </label>
        <label className="field">
          <span>Уязвимые хосты</span>
          <input
            className="input mono"
            value={hosts}
            placeholder="10.10.1.10, 10.10.1.11"
            onChange={(e) => setHosts(e.target.value)}
          />
          <small>IP-адреса из состава объекта через запятую.</small>
        </label>
        <p className="cell-sub">
          CVSS, сведения об эксплуатации и последствия выбираются в карточке после внесения.
        </p>
      </form>
    </Modal>
  );
}
