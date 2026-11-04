import {
  CheckCircle2,
  Download,
  ExternalLink,
  History,
  Radar,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Drawer } from "../components/Drawer";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { apiGet, apiSend } from "../lib/api";
import { formatDateTime, formatNumber } from "../lib/format";
import {
  STATUS_LABELS,
  STATUS_PILL,
  differsFromScanner,
  formatPercent,
  type ObjectMeasure,
} from "../lib/measures";
import {
  CONTROL_STATUS,
  COVERAGE_STATUS,
  MODULE_LABELS,
  failureText,
  runLabel,
  runStatus,
  type Evidence,
  type FailedHost,
  type ImportResult,
  type Recommendation,
  type RunsList,
  type SnapshotBrief,
  type SnapshotFull,
} from "../lib/snapshots";

function message(e: unknown, fallback: string): string {
  return e instanceof Error ? e.message : fallback;
}

function RunPill({ status }: { status: string }) {
  const [label, cls] = runStatus(status);
  return <span className={`pill ${cls}`}>{label}</span>;
}

// ---------- Карточка «Результаты «Сканера»» на вкладке «Меры» ----------

export function ScannerCard({
  objectId,
  snapshot,
  linked,
  canImport,
  onImported,
}: {
  objectId: string;
  snapshot: SnapshotBrief | null;
  linked: boolean;
  canImport: boolean;
  onImported: () => void;
}) {
  const [importing, setImporting] = useState(false);
  const [history, setHistory] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);
  const s = snapshot;

  return (
    <section className="card scanner-card">
      <div className="card-head">
        <h2>
          <Radar size={16} /> Результаты «Сканера»
        </h2>
        <div className="actions">
          {s && (
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => setHistory(true)}
            >
              <History size={14} /> Снимки · {s.number}
            </button>
          )}
          {canImport && linked && (
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={() => setImporting(true)}
            >
              <Download size={14} /> Импортировать прогон
            </button>
          )}
        </div>
      </div>
      <div className="card-pad scanner-body">
        {result && (
          <div className="alert alert-ok" role="status">
            <CheckCircle2 size={15} />
            <span className="alert-text">
              Снимок №{result.snapshot.number} сохранён: статусов изменено —{" "}
              {formatNumber(result.applied)}
              {result.kept_manual > 0 &&
                `, поставленных вручную и расходящихся с «Сканером» — ${formatNumber(result.kept_manual)} (не тронуты)`}
              .
            </span>
          </div>
        )}
        {!linked ? (
          <p className="muted">
            Проект не связан со «Сканером»: укажите номер engagement в карточке
            проекта, чтобы импортировать прогоны.
          </p>
        ) : !s ? (
          <p className="muted">
            Прогоны ещё не импортированы. Импорт сохраняет снимок результата
            прогона по профилю и классу объекта и предлагает статусы мерам с
            проверками «Сканера». Организационные меры оцениваются вручную.
          </p>
        ) : (
          <>
            <div className="scanner-run">
              <span className="tag">Снимок №{s.number}</span>
              <span>
                {runLabel(s)} <RunPill status={s.run_status} />
              </span>
              <span className="muted">
                завершён {formatDateTime(s.run_finished_at)} · импортировал{" "}
                {s.imported_by_name}, {formatDateTime(s.imported_at)}
                {s.selection === "latest" && " · «последний завершённый»"}
              </span>
            </div>
            <div className="scanner-stats">
              <Stat
                label={`«Сканер» · ${s.level ?? ""}`}
                value={formatPercent(s.percent)}
                hint="процент по профилю"
              />
              <Stat
                label="Реализовано"
                value={s.summary.implemented}
                cls="pill-ok"
              />
              <Stat
                label="Частично"
                value={s.summary.partial}
                cls="pill-warn"
              />
              <Stat
                label="Не реализовано"
                value={s.summary.not_implemented}
                cls="pill-danger"
              />
              <Stat
                label="Не проверено"
                value={s.summary.unassessed}
                cls="pill-muted"
              />
            </div>
            {s.coverage_gaps > 0 && (
              <p className="cell-sub">
                Покрытие прогона неполное: {formatNumber(s.coverage_gaps)} пар
                «хост × модуль» не выполнено. Там, где проверки не было,
                отсутствие нарушений не засчитывается — мера остаётся «Не
                оценена».
              </p>
            )}
          </>
        )}
      </div>
      {importing && (
        <ImportDialog
          objectId={objectId}
          onClose={() => setImporting(false)}
          onDone={(r) => {
            setImporting(false);
            setResult(r);
            onImported();
          }}
        />
      )}
      {history && (
        <SnapshotsDrawer
          objectId={objectId}
          onClose={() => setHistory(false)}
        />
      )}
    </section>
  );
}

function Stat({
  label,
  value,
  cls,
  hint,
}: {
  label: string;
  value: number | string | undefined;
  cls?: string;
  hint?: string;
}) {
  return (
    <div className="scanner-stat">
      <span className="kpi-label">
        {cls && <span className={`pill ${cls} pill-dot`} aria-hidden="true" />}
        {label}
      </span>
      <span className="scanner-stat-value" title={hint}>
        {typeof value === "number" ? formatNumber(value) : (value ?? "—")}
      </span>
    </div>
  );
}

// ---------- Выбор прогона ----------

function ImportDialog({
  objectId,
  onClose,
  onDone,
}: {
  objectId: string;
  onClose: () => void;
  onDone: (r: ImportResult) => void;
}) {
  const [list, setList] = useState<RunsList | null>(null);
  const [picked, setPicked] = useState<number | "latest">("latest");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiGet<RunsList>(`/objects/${objectId}/scanner/runs`)
      .then(setList)
      .catch((e: Error) => setError(e.message));
  }, [objectId]);

  const latest = list?.runs.find((r) => r.id === list.latest_id) ?? null;

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      onDone(
        await apiSend<ImportResult>(
          "POST",
          `/objects/${objectId}/scanner/import`,
          { run_id: picked },
        ),
      );
    } catch (e) {
      setError(message(e, "Не удалось импортировать прогон"));
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Импорт результатов прогона"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy || !list || (picked === "latest" && !latest)}
            onClick={submit}
          >
            <Download size={15} /> {busy ? "Импорт…" : "Импортировать"}
          </button>
        </>
      }
    >
      <div className="form-stack">
        {error && <ErrorAlert message={error} />}
        <p className="cell-sub">
          Результат сохранится новым снимком, прежние снимки не меняются.
          Статусы, поставленные вручную, импорт не перезаписывает.
          {list &&
            ` Источник: ${list.source}, проект «Сканера» №${list.engagement_id}.`}
        </p>
        {!list && !error && <Loading />}
        {list && (
          <div
            className="pick-list"
            role="radiogroup"
            aria-label="Прогон для импорта"
          >
            <label
              className={`pick-item${picked === "latest" ? " picked" : ""}`}
            >
              <input
                type="radio"
                name="run"
                checked={picked === "latest"}
                onChange={() => setPicked("latest")}
              />
              <span>
                <strong>Последний завершённый</strong>
                <small className="muted">
                  {" "}
                  {latest
                    ? `· сейчас это прогон №${latest.id}, ${formatDateTime(latest.finished_at)}`
                    : "· завершённых прогонов нет"}
                </small>
              </span>
            </label>
            {list.runs.map((r) => (
              <label
                key={r.id}
                className={`pick-item${picked === r.id ? " picked" : ""}`}
              >
                <input
                  type="radio"
                  name="run"
                  checked={picked === r.id}
                  onChange={() => setPicked(r.id)}
                />
                <span className="tag">№{r.id}</span>
                <span className="run-pick">
                  <span>
                    {r.name ?? "Без названия"} <RunPill status={r.status} />
                  </span>
                  <small className="muted">
                    завершён {formatDateTime(r.finished_at)}
                    {r.snapshots.length > 0 &&
                      ` · уже в снимке №${r.snapshots.join(", №")}`}
                    {r.error_message && ` · ${r.error_message}`}
                  </small>
                </span>
              </label>
            ))}
          </div>
        )}
        {list &&
          typeof picked === "number" &&
          list.runs.find((r) => r.id === picked)?.status === "failed" && (
            <div className="alert alert-warn">
              <span className="alert-text">
                Прогон завершился ошибкой: скорее всего, ни одна мера не
                проверена, и все останутся «Не оценены».
              </span>
            </div>
          )}
      </div>
    </Modal>
  );
}

// ---------- Снимки ----------

function SnapshotsDrawer({
  objectId,
  onClose,
}: {
  objectId: string;
  onClose: () => void;
}) {
  const [list, setList] = useState<SnapshotBrief[] | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [full, setFull] = useState<SnapshotFull | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<SnapshotBrief[]>(`/objects/${objectId}/snapshots`)
      .then((l) => {
        setList(l);
        setOpen(l[0]?.id ?? null);
      })
      .catch((e: Error) => setError(e.message));
  }, [objectId]);

  useEffect(() => {
    if (!open) return;
    setFull(null);
    apiGet<SnapshotFull>(`/snapshots/${open}`)
      .then(setFull)
      .catch((e: Error) => setError(e.message));
  }, [open]);

  return (
    <Drawer
      title="Снимки результатов «Сканера»"
      subtitle="Каждый импорт — отдельный снимок; прежние не меняются"
      onClose={onClose}
    >
      {error && (
        <div className="drawer-section">
          <ErrorAlert message={error} />
        </div>
      )}
      <div className="drawer-section">
        {!list && !error && <Loading />}
        {list && (
          <div className="table-wrap">
            <table className="table table-compact">
              <thead>
                <tr>
                  <th>Снимок</th>
                  <th>Прогон</th>
                  <th className="num">«Сканер»</th>
                  <th>Импорт</th>
                </tr>
              </thead>
              <tbody>
                {list.map((s) => (
                  <tr
                    key={s.id}
                    className={`clickable${open === s.id ? " selected" : ""}`}
                    onClick={() => setOpen(s.id)}
                  >
                    <td className="nowrap">
                      <button
                        type="button"
                        className="link-btn"
                        onClick={() => setOpen(s.id)}
                      >
                        №{s.number}
                      </button>
                      {s.current && (
                        <span className="pill pill-info pill-tight">
                          текущий
                        </span>
                      )}
                    </td>
                    <td>
                      №{s.run_id} <RunPill status={s.run_status} />
                      <div className="cell-sub">
                        {formatDateTime(s.run_finished_at)}
                      </div>
                    </td>
                    <td className="num">{formatPercent(s.percent)}</td>
                    <td className="cell-sub">
                      {s.imported_by_name}
                      <br />
                      {formatDateTime(s.imported_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {open && !full && !error && (
        <div className="drawer-section">
          <Loading />
        </div>
      )}
      {full && <SnapshotDetail s={full} />}
    </Drawer>
  );
}

function SnapshotDetail({ s }: { s: SnapshotFull }) {
  const objectHosts = s.coverage_hosts.filter((h) => h.in_object);
  const outside = s.coverage_hosts.length - objectHosts.length;
  return (
    <>
      <div className="drawer-section">
        <h3>
          Снимок №{s.number} · {runLabel(s)}
        </h3>
        <dl className="props">
          <dt>Профиль и класс</dt>
          <dd>
            {s.profile_id} · {s.level ?? "—"}
            {s.adaptation_version && (
              <span className="muted">
                {" "}
                · адаптация v{s.adaptation_version}
              </span>
            )}
          </dd>
          <dt>Процент «Сканера»</dt>
          <dd>
            {formatPercent(s.percent)}{" "}
            <span className="muted">
              (выполнено {s.counts.passed ?? 0}, не выполнено{" "}
              {s.counts.failed ?? 0}, не проверено {s.counts.na ?? 0}, вручную{" "}
              {s.counts.manual ?? 0})
            </span>
          </dd>
          <dt>Источник</dt>
          <dd>{s.source}</dd>
        </dl>
      </div>
      <div className="drawer-section">
        <h3>Покрытие хостов объекта</h3>
        {s.missing_hosts.length > 0 && (
          <p className="cell-sub">
            Не входили в прогон: {s.missing_hosts.join(", ")}
          </p>
        )}
        <div className="table-wrap">
          <table className="table table-compact">
            <thead>
              <tr>
                <th>Хост</th>
                <th>Итог</th>
                <th>Пробелы</th>
              </tr>
            </thead>
            <tbody>
              {objectHosts.map((h) => {
                const [label, cls] = COVERAGE_STATUS[h.status ?? ""] ?? [
                  h.status ?? "—",
                  "pill-muted",
                ];
                const gaps = Object.entries(h.modules).filter(
                  ([, m]) =>
                    m.status !== "completed" && m.status !== "not_applicable",
                );
                return (
                  <tr key={h.host}>
                    <td className="mono nowrap">{h.host}</td>
                    <td>
                      <span className={`pill ${cls}`}>{label}</span>
                    </td>
                    <td className="cell-sub">
                      {gaps.length === 0
                        ? "—"
                        : gaps
                            .map(
                              ([mod, m]) =>
                                `${MODULE_LABELS[mod] ?? mod}: ${m.label ?? m.status}`,
                            )
                            .join("; ")}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {outside > 0 && (
          <p className="cell-sub">
            Ещё {outside} хостов прогона вне объекта — в оценку не входят.
          </p>
        )}
      </div>
      <div className="drawer-section">
        <h3>Меры с проверками «Сканера»</h3>
        <div className="table-wrap">
          <table className="table table-compact">
            <thead>
              <tr>
                <th>Мера</th>
                <th>«Сканер»</th>
                <th>По объекту</th>
              </tr>
            </thead>
            <tbody>
              {s.controls.map((c) => {
                const [label, cls] = CONTROL_STATUS[c.status];
                return (
                  <tr key={c.id}>
                    <td>
                      <span className="tag">{c.id}</span>
                    </td>
                    <td className="nowrap">
                      <span className={`pill ${cls}`}>{label}</span>
                    </td>
                    <td>
                      {c.measure_status ? (
                        <>
                          <span
                            className={`pill ${STATUS_PILL[c.measure_status]}`}
                          >
                            {STATUS_LABELS[c.measure_status]}
                          </span>
                          <div className="cell-sub">{c.note}</div>
                        </>
                      ) : (
                        <span className="muted">не в наборе объекта</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

// ---------- Раздел «Результат «Сканера»» в карточке меры ----------

export function MeasureEvidence({
  m,
  canAssess,
  onChanged,
}: {
  m: ObjectMeasure;
  canAssess: boolean;
  onChanged: () => void;
}) {
  const [list, setList] = useState<Evidence[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    apiGet<Evidence[]>(`/object-measures/${m.id}/evidence`)
      .then(setList)
      .catch((e: Error) => setError(e.message));
  }, [m.id]);
  useEffect(load, [load]);

  async function useAuto() {
    setBusy(true);
    setError(null);
    try {
      await apiSend("PATCH", `/object-measures/${m.id}`, { use_auto: true });
      onChanged();
    } catch (e) {
      setError(message(e, "Не удалось принять предложение"));
      setBusy(false);
    }
  }

  const scanner = (list ?? []).filter((e) => e.kind === "scanner");
  const last = scanner[0];
  const differs = differsFromScanner(m);

  return (
    <div className="drawer-section">
      <h3>Результат «Сканера»</h3>
      {error && <ErrorAlert message={error} />}
      {!list && !error && <Loading />}
      {list && !last && (
        <p className="muted">
          Прогоны ещё не импортированы — автоматических доказательств нет.
        </p>
      )}
      {last && (
        <>
          <dl className="props">
            <dt>Предложение</dt>
            <dd>
              {last.status && (
                <span className={`pill ${STATUS_PILL[last.status]}`}>
                  {STATUS_LABELS[last.status]}
                </span>
              )}{" "}
              <span className="muted">{last.summary}</span>
            </dd>
            <dt>Снимок</dt>
            <dd>
              {last.snapshot ? (
                <>
                  №{last.snapshot.number} · {runLabel(last.snapshot)},{" "}
                  {formatDateTime(last.snapshot.run_finished_at)}
                  {!last.snapshot.current && (
                    <span className="muted"> · не текущий</span>
                  )}
                </>
              ) : (
                "—"
              )}
            </dd>
            <dt>Хосты объекта</dt>
            <dd>
              проверено {last.data.checked.length} из {last.data.hosts.length}
              {last.data.failed.length > 0 &&
                `, с нарушениями ${last.data.failed.length}`}
              {last.data.not_applicable.length > 0 &&
                `, неприменимо ${last.data.not_applicable.length}`}
            </dd>
          </dl>
          {differs && (
            <div className="alert alert-warn">
              <span className="alert-text">
                {m.status_source === "manual"
                  ? "Статус поставлен вручную"
                  : "Статус подтверждён"}{" "}
                ({STATUS_LABELS[m.status]}) и расходится с предложением
                «Сканера».
              </span>
              {canAssess && (
                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={busy}
                  onClick={useAuto}
                >
                  Принять предложение
                </button>
              )}
            </div>
          )}
          {last.data.failed_hosts.length > 0 && (
            <FailedHosts hosts={last.data.failed_hosts} />
          )}
          {last.data.unchecked.length > 0 && (
            <div className="evidence-block">
              <h4>Не проверено</h4>
              <ul className="evidence-list">
                {last.data.unchecked.map((u) => (
                  <li key={u.host}>
                    <span className="mono">{u.host}</span>{" "}
                    <span className="muted">— {u.reason}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {last.data.outside_failed.length > 0 && (
            <p className="cell-sub">
              Нарушения вне объекта (в оценку не входят):{" "}
              {last.data.outside_failed.join(", ")}
            </p>
          )}
          {last.data.recommendations.length > 0 && (
            <Recommendations items={last.data.recommendations} />
          )}
          {scanner.length > 1 && (
            <div className="evidence-block">
              <h4>Прежние снимки</h4>
              <ul className="evidence-list">
                {scanner.slice(1).map((e) => (
                  <li key={e.id}>
                    {e.snapshot
                      ? `№${e.snapshot.number} · прогон №${e.snapshot.run_id}`
                      : "—"}{" "}
                    {e.status && (
                      <span className={`pill ${STATUS_PILL[e.status]}`}>
                        {STATUS_LABELS[e.status]}
                      </span>
                    )}{" "}
                    <span className="muted">{e.summary}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function FailedHosts({ hosts }: { hosts: FailedHost[] }) {
  return (
    <div className="evidence-block">
      <h4>Нарушения по хостам</h4>
      <ul className="evidence-list">
        {hosts.map((h) => (
          <li key={h.host}>
            <span className="mono">{h.host}</span>
            <ul>
              {h.checks.map((c) => (
                <li key={c.id}>
                  <span className="tag">{c.id}</span>{" "}
                  <span className="muted">
                    {c.failures.map(failureText).join("; ") || "нарушение"}
                    {c.more > 0 && ` и ещё ${c.more}`}
                  </span>
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Recommendations({ items }: { items: Recommendation[] }) {
  return (
    <div className="evidence-block">
      <h4>Рекомендации</h4>
      <ul className="evidence-list">
        {items.map((r) => (
          <li key={r.check}>
            <strong>{r.title}</strong>
            {r.remediation && <div className="cell-sub">{r.remediation}</div>}
            {r.doc && (
              <a
                className="cell-sub"
                href={r.doc}
                target="_blank"
                rel="noreferrer noopener"
              >
                Документация <ExternalLink size={12} />
              </a>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
