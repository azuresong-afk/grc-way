import { AlertTriangle, ArrowLeft, CheckCheck, GitCompareArrows, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { apiGet, apiSend } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDateTime, formatNumber } from "../lib/format";

type Action = "add" | "update" | "remove";
type Value = string | string[] | null;

interface FieldChange {
  field: string;
  before: Value;
  after: Value;
}

export interface DiffItem {
  key: string;
  profile_id: string;
  measure_id: string;
  action: Action;
  title: string;
  group_code: string;
  fields: FieldChange[];
  origin: string | null;
  revision: number | null;
  verified: boolean;
  conflict: boolean;
  default: boolean;
}

interface DiffProfile {
  id: string;
  title: string;
  status: "new" | "changed" | "same" | "missing";
  fields: FieldChange[];
  groups: { code: string; action: Action; before: string | null; after: string | null }[];
  counts: Record<"add" | "update" | "remove" | "unchanged" | "conflict", number>;
  total: number;
}

interface Summary {
  add: number;
  update: number;
  remove: number;
  unchanged: number;
  conflict: number;
  verified_affected: number;
  profiles_new: number;
  profiles_changed: number;
  profiles_missing: number;
  checks_added: number;
  checks_changed: number;
  has_changes: boolean;
}

interface DiffBrief {
  id: string;
  created_at: string;
  created_by_name: string | null;
  mode: string;
  source: string;
  status: "pending" | "applied" | "superseded";
  summary: Summary;
  applied_at: string | null;
  applied_by_name: string | null;
  applied: Record<string, number | boolean | string[]> | null;
}

export interface Diff extends DiffBrief {
  profiles: DiffProfile[];
  items: DiffItem[];
  checks: {
    added: { id: string; title: string; platform: string }[];
    changed: { id: string; fields: FieldChange[] }[];
  };
}

interface SourceInfo {
  mode: string;
  source: string;
  last_synced_at: string | null;
  pending_diff_id: string | null;
}

const FIELD: Record<string, string> = {
  title: "Наименование",
  short: "Краткое наименование",
  document: "Документ",
  url: "Ссылка",
  level_label: "Название уровня",
  levels: "Уровни",
  default_level: "Уровень по умолчанию",
  dynamic: "Динамический профиль",
  group_code: "Группа",
  checks: "Проверки «Сканера»",
  platform: "Платформа",
};

const ACTION: Record<Action, [string, string]> = {
  add: ["Добавлена", "pill-ok"],
  update: ["Изменена", "pill-info"],
  remove: ["Удалена", "pill-danger"],
};

const STATUS: Record<DiffBrief["status"], [string, string]> = {
  pending: ["Ждёт применения", "pill-warn"],
  applied: ["Применено", "pill-ok"],
  superseded: ["Устарело", "pill-muted"],
};

type Filter = "all" | Action | "conflict";
const FILTERS: [Filter, string, keyof Summary | null][] = [
  ["all", "Все", null],
  ["add", "Добавлено", "add"],
  ["update", "Изменено", "update"],
  ["remove", "Удалено", "remove"],
  ["conflict", "Конфликты", "conflict"],
];

function summaryLine(s: Summary): string {
  if (!s.has_changes) return "без изменений";
  const parts = [
    s.add && `+${formatNumber(s.add)}`,
    s.update && `~${formatNumber(s.update)}`,
    s.remove && `−${formatNumber(s.remove)}`,
  ].filter(Boolean);
  return parts.length ? parts.join(" ") : "изменены профили или проверки";
}

/** Значение «было → стало»: списки — по элементам, строки — целиком. */
function ValueDiff({ before, after }: { before: Value; after: Value }) {
  if (Array.isArray(before) || Array.isArray(after)) {
    const b = (before as string[] | null) ?? [];
    const a = (after as string[] | null) ?? [];
    const all = [...b, ...a.filter((x) => !b.includes(x))];
    if (!all.length) return <span className="muted">пусто</span>;
    return (
      <span className="diff-tokens">
        {all.map((x) =>
          !a.includes(x) ? (
            <del key={x} className="diff-del" title="Убрано">
              {x}
            </del>
          ) : !b.includes(x) && before !== null ? (
            <ins key={x} className="diff-ins" title="Добавлено">
              {x}
            </ins>
          ) : (
            <span key={x} className="diff-same">
              {x}
            </span>
          ),
        )}
      </span>
    );
  }
  if (before === null) return <span>{after}</span>;
  if (after === null) return <del className="diff-del">{before}</del>;
  return (
    <span className="diff-text">
      <del className="diff-del">{before}</del>
      <span className="muted" aria-hidden="true">
        →
      </span>
      <ins className="diff-ins">{after}</ins>
    </span>
  );
}

function Fields({ fields, labels }: { fields: FieldChange[]; labels?: Record<string, string> }) {
  return (
    <dl className="diff-fields">
      {fields.map((f) => (
        <div key={f.field}>
          <dt>{labels?.[f.field] ?? FIELD[f.field] ?? f.field}</dt>
          <dd>
            <ValueDiff before={f.before} after={f.after} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

export function ScannerSyncPage() {
  const { can } = useAuth();
  const canManage = can("refs.manage");
  const [params, setParams] = useSearchParams();
  const diffId = params.get("diff");
  const filter = (params.get("filter") as Filter | null) ?? "all";

  const [source, setSource] = useState<SourceInfo | null>(null);
  const [history, setHistory] = useState<DiffBrief[] | null>(null);
  const [diff, setDiff] = useState<Diff | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"diff" | "apply" | null>(null);
  const [confirm, setConfirm] = useState(false);

  const setParam = (patch: Record<string, string>) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        for (const [k, v] of Object.entries(patch)) {
          if (v) next.set(k, v);
          else next.delete(k);
        }
        return next;
      },
      { replace: true },
    );

  const showDiff = useCallback((d: Diff) => {
    setDiff(d);
    setSelected(new Set(d.items.filter((i) => i.default).map((i) => i.key)));
  }, []);

  const loadMeta = useCallback(() => {
    Promise.all([
      apiGet<SourceInfo>("/refs/scanner-source"),
      apiGet<DiffBrief[]>("/refs/scanner-diffs?limit=10"),
    ])
      .then(([s, h]) => {
        setSource(s);
        setHistory(h);
        if (!diffId && s.pending_diff_id) setParam({ diff: s.pending_diff_id });
      })
      .catch((e: Error) => setError(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [diffId]);

  useEffect(loadMeta, [loadMeta]);

  useEffect(() => {
    if (!diffId) {
      setDiff(null);
      return;
    }
    if (diff?.id === diffId) return;
    setDiff(null);
    apiGet<Diff>(`/refs/scanner-diffs/${diffId}`)
      .then(showDiff)
      .catch((e: Error) => setError(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [diffId, showDiff]);

  const compare = () => {
    setBusy("diff");
    setError(null);
    apiSend<Diff>("POST", "/refs/profiles/scanner-diff")
      .then((d) => {
        showDiff(d);
        setParam({ diff: d.id, filter: "" });
        loadMeta();
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setBusy(null));
  };

  const apply = () => {
    if (!diff) return;
    setBusy("apply");
    setError(null);
    apiSend<Diff>("POST", "/refs/profiles/scanner-apply", {
      diff_id: diff.id,
      selected: [...selected],
    })
      .then((d) => {
        setConfirm(false);
        showDiff(d);
        loadMeta();
      })
      .catch((e: Error) => {
        setConfirm(false);
        setError(e.message);
      })
      .finally(() => setBusy(null));
  };

  const pending = diff?.status === "pending";
  const editable = pending && canManage;

  const visible = useMemo(() => {
    const items = diff?.items ?? [];
    if (filter === "all") return items;
    if (filter === "conflict") return items.filter((i) => i.conflict);
    return items.filter((i) => i.action === filter);
  }, [diff, filter]);

  const byProfile = useMemo(() => {
    const out = new Map<string, DiffItem[]>();
    for (const i of visible) out.set(i.profile_id, [...(out.get(i.profile_id) ?? []), i]);
    return out;
  }, [visible]);

  const toggle = (keys: string[], on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      for (const k of keys) {
        if (on) next.add(k);
        else next.delete(k);
      }
      return next;
    });

  // В применённом сравнении — какие изменения администратор не выбрал.
  const applied = diff?.status === "applied" ? diff.applied?.selected : undefined;
  const skipped = new Set(
    Array.isArray(applied)
      ? (diff?.items ?? []).map((i) => i.key).filter((k) => !applied.includes(k))
      : [],
  );
  const chosen = diff?.items.filter((i) => selected.has(i.key)) ?? [];
  const count = (a: Action) => chosen.filter((i) => i.action === a).length;
  const profileChanges =
    diff?.profiles.filter(
      (p) => p.status !== "same" && (p.status !== "changed" || p.fields.length || p.groups.length),
    ) ?? [];
  const checksChanged = (diff?.checks.added.length ?? 0) + (diff?.checks.changed.length ?? 0);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            <Link to="/refs">Справочники</Link> / Профили мер
          </div>
          <h1>Обновление из «Сканера»</h1>
        </div>
        <div className="actions">
          <Link to="/refs" className="btn btn-ghost">
            <ArrowLeft size={15} /> К справочнику
          </Link>
          {canManage && (
            <button
              type="button"
              className="btn btn-primary"
              onClick={compare}
              disabled={busy !== null}
            >
              <RefreshCw size={15} className={busy === "diff" ? "spin" : undefined} />
              {busy === "diff" ? "Сравниваем…" : "Сравнить со «Сканером»"}
            </button>
          )}
        </div>
      </div>

      {source && (
        <div className="alert alert-info">
          <GitCompareArrows size={15} />
          <span className="alert-text">
            Источник:{" "}
            <b>{source.mode === "live" ? "API «Сканера»" : "сохранённый ответ «Сканера»"}</b>{" "}
            <span className="mono">{source.source}</span>,{" "}
            <span className="mono">GET /compliance/profiles</span>. Последнее обновление
            справочника: {formatDateTime(source.last_synced_at)}.
            <br />
            Сравнение ничего не меняет. Меры обновляются только после «Применить», с новой ревизией
            и записью в журнале; изменённые меры снова требуют сверки методистом.
          </span>
        </div>
      )}

      {error && <ErrorAlert message={error} />}

      {!diffId && source && !error && (
        <section className="card">
          <EmptyState
            icon={<GitCompareArrows size={21} />}
            title="Сравнений ещё не было"
            text={
              canManage
                ? "Нажмите «Сравнить со «Сканером»», чтобы увидеть добавленные, изменённые и удалённые меры."
                : "Сравнение и применение выполняет администратор."
            }
          />
        </section>
      )}

      {diffId && !diff && !error && <Loading />}

      {diff && (
        <>
          <DiffStatus diff={diff} />

          <div className="kpi-row diff-kpis">
            {FILTERS.slice(1).map(([value, label, key]) => (
              <button
                key={value}
                type="button"
                className={`card kpi kpi-btn${filter === value ? " active" : ""}`}
                aria-pressed={filter === value}
                onClick={() => setParam({ filter: filter === value ? "" : value })}
              >
                <span className="kpi-label">{label}</span>
                <span
                  className={`kpi-value${value === "conflict" && diff.summary.conflict ? " warn" : ""}`}
                >
                  {formatNumber(diff.summary[key as "add"] as number)}
                </span>
              </button>
            ))}
            <div className="card kpi">
              <span className="kpi-label">Без изменений</span>
              <span className="kpi-value muted">{formatNumber(diff.summary.unchanged)}</span>
            </div>
          </div>

          {pending && (diff.summary.conflict > 0 || diff.summary.verified_affected > 0) && (
            <div className="alert alert-warn">
              <AlertTriangle size={15} />
              <span className="alert-text">
                {diff.summary.conflict > 0 && (
                  <>
                    Конфликтов: {formatNumber(diff.summary.conflict)} — меры, исправленные в
                    интерфейсе. По умолчанию они не применяются; отметьте меру, если версия
                    «Сканера» верна, — правка уйдёт в историю.
                  </>
                )}
                {diff.summary.conflict > 0 && diff.summary.verified_affected > 0 && <br />}
                {diff.summary.verified_affected > 0 && (
                  <>
                    Затронуто сверенных методистом мер:{" "}
                    {formatNumber(diff.summary.verified_affected)}. После применения отметка о
                    сверке с них снимается.
                  </>
                )}
              </span>
            </div>
          )}

          {profileChanges.length > 0 && (
            <section className="card">
              <div className="card-head">
                <h2>Профили и группы</h2>
              </div>
              <div className="card-pad diff-profiles">
                {profileChanges.map((p) => (
                  <div key={p.id} className="diff-profile">
                    <div className="diff-profile-head">
                      <span className="tag">{p.id}</span> <b>{p.title}</b>{" "}
                      {p.status === "new" && (
                        <span className="pill pill-ok">Новый профиль, мер: {p.total}</span>
                      )}
                      {p.status === "missing" && (
                        <span className="pill pill-warn">
                          Нет в ответе «Сканера» — не удаляется
                        </span>
                      )}
                    </div>
                    {p.fields.length > 0 && <Fields fields={p.fields} />}
                    {p.groups.length > 0 && (
                      <dl className="diff-fields">
                        {p.groups.map((g) => (
                          <div key={g.code}>
                            <dt>
                              Группа <span className="tag">{g.code}</span>
                            </dt>
                            <dd>
                              <ValueDiff before={g.before} after={g.after} />
                              {g.action === "remove" && (
                                <span className="muted">
                                  {" "}
                                  — убирается, если в ней не останется мер
                                </span>
                              )}
                            </dd>
                          </div>
                        ))}
                      </dl>
                    )}
                  </div>
                ))}
              </div>
            </section>
          )}

          {diff.items.length > 0 && (
            <div className="chips" role="group" aria-label="Фильтр изменений">
              {FILTERS.map(([value, label, key]) => (
                <button
                  key={value}
                  type="button"
                  className="chip"
                  aria-pressed={filter === value}
                  onClick={() => setParam({ filter: value === "all" ? "" : value })}
                >
                  {label}
                  {key && (
                    <span className="count">{formatNumber(diff.summary[key] as number)}</span>
                  )}
                </button>
              ))}
            </div>
          )}

          {diff.items.length > 0 && visible.length === 0 && (
            <section className="card">
              <EmptyState
                icon={<CheckCheck size={21} />}
                title="Ничего не найдено"
                text="Под выбранный фильтр изменений нет."
              />
            </section>
          )}

          {[...byProfile.entries()].map(([pid, items]) => {
            const title = diff.profiles.find((p) => p.id === pid)?.title ?? pid;
            const keys = items.map((i) => i.key);
            const all = keys.every((k) => selected.has(k));
            return (
              <section key={pid} className="card">
                <div className="card-head">
                  <h2>
                    <span className="tag">{pid}</span> {title}
                  </h2>
                  <span className="count">{items.length}</span>
                </div>
                <div className="table-wrap">
                  <table className="table diff-table">
                    <thead>
                      <tr>
                        {editable && (
                          <th className="cell-check">
                            <input
                              type="checkbox"
                              aria-label={`Выбрать все изменения ${title}`}
                              checked={all}
                              onChange={(e) => toggle(keys, e.target.checked)}
                            />
                          </th>
                        )}
                        <th>Мера</th>
                        <th>Наименование</th>
                        <th>Что меняется</th>
                        <th>Отметки</th>
                      </tr>
                    </thead>
                    <tbody>
                      {items.map((i) => (
                        <tr
                          key={i.key}
                          className={editable && !selected.has(i.key) ? "row-off" : undefined}
                        >
                          {editable && (
                            <td className="cell-check">
                              <input
                                type="checkbox"
                                aria-label={`Применить ${i.measure_id}`}
                                checked={selected.has(i.key)}
                                onChange={(e) => toggle([i.key], e.target.checked)}
                              />
                            </td>
                          )}
                          <td className="nowrap diff-id">
                            <span className="tag">{i.measure_id}</span>
                          </td>
                          <td className="diff-title">{i.title}</td>
                          <td className="diff-change">
                            {i.action === "remove" ? (
                              <span className="muted">
                                Меры нет в каталоге «Сканера». Удаляется, история сохраняется.
                              </span>
                            ) : (
                              <Fields
                                fields={i.fields.filter(
                                  (f) => i.action === "update" || f.field !== "title",
                                )}
                              />
                            )}
                          </td>
                          <td className="diff-marks">
                            <div className="pill-stack">
                              <span className={`pill ${ACTION[i.action][1]}`}>
                                {ACTION[i.action][0]}
                              </span>
                              {i.conflict && (
                                <span className="pill pill-warn">Правка в интерфейсе</span>
                              )}
                              {i.verified && (
                                <span className="pill pill-muted">Сверка снимется</span>
                              )}
                              {skipped.has(i.key) && (
                                <span className="pill pill-muted">Не применена</span>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            );
          })}

          {checksChanged > 0 && (
            <section className="card">
              <div className="card-head">
                <h2>Каталог проверок «Сканера»</h2>
                <span className="count">{checksChanged}</span>
              </div>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Проверка</th>
                      <th>Что меняется</th>
                    </tr>
                  </thead>
                  <tbody>
                    {diff.checks.added.map((c) => (
                      <tr key={c.id}>
                        <td className="nowrap">
                          <span className="tag">{c.id}</span>
                        </td>
                        <td>
                          <span className="pill pill-ok">Новая</span> {c.title}
                        </td>
                      </tr>
                    ))}
                    {diff.checks.changed.map((c) => (
                      <tr key={c.id}>
                        <td className="nowrap">
                          <span className="tag">{c.id}</span>
                        </td>
                        <td>
                          <Fields fields={c.fields} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {editable && diff.summary.has_changes && (
            <div className="apply-bar">
              <span>
                Выбрано {formatNumber(chosen.length)} из {formatNumber(diff.items.length)}
                {diff.items.length - chosen.length > 0 && (
                  <span className="muted"> · не выбранные останутся как есть</span>
                )}
              </span>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setConfirm(true)}
                disabled={busy !== null}
              >
                Применить…
              </button>
            </div>
          )}
        </>
      )}

      {history && history.length > 0 && (
        <section className="card">
          <div className="card-head">
            <h2>История сравнений</h2>
          </div>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Когда</th>
                  <th>Кто</th>
                  <th>Источник</th>
                  <th>Разница</th>
                  <th>Статус</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr
                    key={h.id}
                    className={`clickable${h.id === diffId ? " selected" : ""}`}
                    onClick={() => setParam({ diff: h.id, filter: "" })}
                  >
                    <td className="nowrap">
                      <button
                        type="button"
                        className="link-btn"
                        onClick={() => setParam({ diff: h.id, filter: "" })}
                      >
                        {formatDateTime(h.created_at)}
                      </button>
                    </td>
                    <td>{h.created_by_name ?? "—"}</td>
                    <td className="mono">{h.source}</td>
                    <td className="nowrap mono">{summaryLine(h.summary)}</td>
                    <td>
                      <span className={`pill ${STATUS[h.status][1]}`}>{STATUS[h.status][0]}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {confirm && diff && (
        <Modal
          title="Применить изменения из «Сканера»"
          onClose={() => setConfirm(false)}
          footer={
            <>
              <button type="button" className="btn" onClick={() => setConfirm(false)}>
                Отмена
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={apply}
                disabled={busy !== null}
              >
                {busy === "apply" ? "Применяем…" : "Применить"}
              </button>
            </>
          }
        >
          <dl className="props">
            <dt>Добавить</dt>
            <dd>{formatNumber(count("add"))}</dd>
            <dt>Изменить</dt>
            <dd>{formatNumber(count("update"))}</dd>
            <dt>Удалить</dt>
            <dd>{formatNumber(count("remove"))}</dd>
            <dt>Пропустить</dt>
            <dd>{formatNumber(diff.items.length - chosen.length)}</dd>
          </dl>
          <p className="muted">
            Изменения профилей, групп и каталога проверок применяются вместе с мерами. Каждая мера
            получит новую ревизию, прежняя версия останется в истории; всё попадёт в журнал аудита.
          </p>
        </Modal>
      )}
    </>
  );
}

function DiffStatus({ diff }: { diff: Diff }) {
  const head = `Сравнение от ${formatDateTime(diff.created_at)}${diff.created_by_name ? `, ${diff.created_by_name}` : ""}`;
  if (diff.status === "applied") {
    const a = diff.applied ?? {};
    return (
      <div className="alert alert-ok">
        <CheckCheck size={15} />
        <span className="alert-text">
          {head}.{" "}
          {a.no_changes
            ? "Справочник совпадает с каталогом «Сканера»."
            : `Применено ${formatDateTime(diff.applied_at)}, ${diff.applied_by_name ?? "—"}: добавлено ${a.added ?? 0}, изменено ${a.updated ?? 0}, удалено ${a.removed ?? 0}, пропущено ${a.skipped ?? 0}.`}
        </span>
      </div>
    );
  }
  if (diff.status === "superseded") {
    return (
      <div className="alert alert-warn">
        <span className="alert-text">
          {head}. Есть более новое сравнение — это уже нельзя применить.
        </span>
      </div>
    );
  }
  return (
    <div className="alert alert-info">
      <GitCompareArrows size={15} />
      <span className="alert-text">
        {head}. Ждёт решения администратора: изменения ещё не применены.
      </span>
    </div>
  );
}
