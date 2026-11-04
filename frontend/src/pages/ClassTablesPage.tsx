import { CheckCheck, ExternalLink, Pencil, Table2 } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ClassTrace } from "../components/ClassTrace";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { VerifyBadge } from "../components/VerifyBadge";
import { apiGet, apiSend } from "../lib/api";
import { useAuth } from "../lib/auth";
import {
  ORIGIN_LABELS,
  describeWhen,
  sourceText,
  type Definition,
  type Row,
  type Source,
  type Table,
  type TableBrief,
} from "../lib/classification";
import { formatDateTime } from "../lib/format";

export function ClassTablesPage() {
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const [list, setList] = useState<TableBrief[] | null>(null);
  const [table, setTable] = useState<Table | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editRow, setEditRow] = useState<{ step: string; row: Row } | null>(null);
  const [editSource, setEditSource] = useState(false);
  const regime = params.get("regime") ?? "117";

  const loadList = useCallback(() => {
    apiGet<TableBrief[]>("/refs/classification-tables")
      .then(setList)
      .catch((e: Error) => setError(e.message));
  }, []);

  const loadTable = useCallback(() => {
    setError(null);
    setTable(null);
    apiGet<Table>(`/refs/classification-tables/${regime}`)
      .then(setTable)
      .catch((e: Error) => setError(e.message));
  }, [regime]);

  useEffect(loadList, [loadList]);
  useEffect(loadTable, [loadTable]);

  const changed = (t: Table) => {
    setTable(t);
    loadList();
  };

  async function verify() {
    if (!table) return;
    try {
      changed(
        await apiSend<Table>("POST", `/refs/classification-tables/${table.regime}/verify`, {
          revision: table.revision,
        }),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось отметить сверку");
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            <Link to="/refs">Справочники</Link> / Классификация
          </div>
          <h1>Таблицы классификации</h1>
        </div>
      </div>

      {list && (
        <div className="tabs" role="tablist" aria-label="Нормативный режим">
          {list.map((t) => (
            <button
              key={t.regime}
              type="button"
              role="tab"
              className="tab"
              aria-selected={t.regime === regime}
              onClick={() => setParams({ regime: t.regime }, { replace: true })}
            >
              {t.regime_title}
              {!t.verified && <span className="count count-warn">!</span>}
            </button>
          ))}
        </div>
      )}

      {list?.length === 0 && (
        <section className="card">
          <EmptyState
            icon={<Table2 size={21} />}
            title="Таблицы не загружены"
            text="Таблицы загружаются из reference/classification при старте сервиса."
          />
        </section>
      )}

      {error && <ErrorAlert message={error} onRetry={loadTable} />}
      {!table && !error && list?.length !== 0 && <Loading />}

      {table && (
        <>
          <div className={`alert ${table.verified ? "alert-ok" : "alert-warn"}`}>
            <span className="alert-text">
              {table.verified ? (
                <>
                  Сверено методистом: {table.verified_by_name}, {formatDateTime(table.verified_at)}.
                </>
              ) : (
                <>
                  Таблица не сверена методистом. Расчёты по ней утверждаются только с явным подтверждением
                  утверждающего.
                </>
              )}{" "}
              {table.source.note}
            </span>
          </div>

          <div className="row-phi">
            <section className="card">
              <div className="card-head">
                <h2>{table.title}</h2>
                <VerifyBadge verified={table.verified} by={table.verified_by_name} at={table.verified_at} />
              </div>
              <dl className="props card-pad">
                <dt>Документ</dt>
                <dd>
                  {sourceText(table.source) || "—"}
                  {table.source.url && (
                    <>
                      {" "}
                      <a href={table.source.url} target="_blank" rel="noreferrer noopener">
                        Текст <ExternalLink size={12} />
                      </a>
                    </>
                  )}
                </dd>
                <dt>Версия</dt>
                <dd>
                  {table.version} <span className="muted">· ревизия {table.revision}</span>
                </dd>
                <dt>Происхождение</dt>
                <dd>{ORIGIN_LABELS[table.origin] ?? table.origin}</dd>
                <dt>Полнота</dt>
                <dd>
                  {table.gaps === 0 ? (
                    "Любое сочетание исходных данных даёт результат"
                  ) : (
                    <span className="pill pill-danger">Не покрыто сочетаний: {table.gaps}</span>
                  )}
                </dd>
              </dl>
              <div className="card-pad actions">
                {can("refs.manage") && (
                  <button type="button" className="btn" onClick={() => setEditSource(true)}>
                    <Pencil size={15} /> Источник и версия
                  </button>
                )}
                {can("refs.verify") && !table.verified && (
                  <button type="button" className="btn btn-primary" onClick={verify}>
                    <CheckCheck size={15} /> Сверено с текстом
                  </button>
                )}
              </div>
            </section>

            <section className="card">
              <div className="card-head">
                <h2>История правок</h2>
                <span className="count">{table.revisions.length}</span>
              </div>
              {table.revisions.length === 0 ? (
                <p className="card-pad muted">Таблица не менялась с загрузки.</p>
              ) : (
                <ul className="history card-pad">
                  {table.revisions.map((r) => (
                    <li key={r.revision}>
                      <span className="cell-title">
                        Ревизия {r.revision} → {r.revision + 1}
                      </span>
                      <span className="cell-sub">
                        {formatDateTime(r.changed_at)}, {r.changed_by_name ?? "—"}
                        {r.comment && ` · ${r.comment}`}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>

          <section className="card">
            <div className="card-head">
              <h2>Исходные данные</h2>
            </div>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Поле</th>
                    <th>Варианты</th>
                  </tr>
                </thead>
                <tbody>
                  {table.definition.inputs.map((i) => (
                    <tr key={i.key}>
                      <td>
                        <span className="cell-title">{i.label}</span>
                        {i.help && <div className="cell-sub">{i.help}</div>}
                      </td>
                      <td>{i.options.map((o) => o.label).join(" · ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <section className="card">
            <div className="card-head">
              <h2>Расчёт</h2>
            </div>
            <div className="card-pad">
              <ClassTrace
                definition={table.definition}
                trace={[]}
                inputs={{}}
                tableSource={table.source}
                onRow={
                  can("refs.manage")
                    ? (step, id) => {
                        const row = table.definition.steps.find((s) => s.key === step)?.rows?.find((r) => r.id === id);
                        if (row) setEditRow({ step, row });
                      }
                    : undefined
                }
              />
            </div>
          </section>
        </>
      )}

      {editRow && table && (
        <RowDialog
          table={table}
          step={editRow.step}
          row={editRow.row}
          onClose={() => setEditRow(null)}
          onSaved={(t) => {
            setEditRow(null);
            changed(t);
          }}
        />
      )}
      {editSource && table && (
        <SourceDialog
          table={table}
          onClose={() => setEditSource(false)}
          onSaved={(t) => {
            setEditSource(false);
            changed(t);
          }}
        />
      )}
    </>
  );
}

/** Значения, которые может дать шаг: объявленные, итоговые (для последнего шага) и уже встречающиеся. */
function stepValues(def: Definition, stepKey: string): string[] {
  const step = def.steps.find((s) => s.key === stepKey);
  const out = new Set<string>();
  step?.values?.forEach((v) => out.add(v.value));
  if (def.result.key === stepKey) def.result.values.forEach((v) => out.add(v.value));
  step?.rows?.forEach((r) => out.add(r.value));
  return [...out];
}

function RowDialog({
  table,
  step,
  row,
  onClose,
  onSaved,
}: {
  table: Table;
  step: string;
  row: Row;
  onClose: () => void;
  onSaved: (t: Table) => void;
}) {
  const def = table.definition;
  const [value, setValue] = useState(row.value);
  const [clause, setClause] = useState(row.source?.clause ?? "");
  const [note, setNote] = useState(row.note ?? "");
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const next: Definition = structuredClone(def);
    const target = next.steps.find((s) => s.key === step)?.rows?.find((r) => r.id === row.id);
    if (!target) return;
    target.value = value;
    const source = { ...(target.source ?? {}) };
    if (clause.trim()) source.clause = clause.trim();
    else delete source.clause;
    if (Object.keys(source).length) target.source = source;
    else delete target.source;
    if (note.trim()) target.note = note.trim();
    else delete target.note;
    try {
      onSaved(
        await apiSend<Table>("PATCH", `/refs/classification-tables/${table.regime}`, {
          definition: next,
          comment: comment.trim(),
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось сохранить");
      setBusy(false);
    }
  }

  return (
    <Modal
      title={`Строка ${row.id}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="row-edit" className="btn btn-primary" disabled={busy || !comment.trim()}>
            Сохранить
          </button>
        </>
      }
    >
      <form id="row-edit" className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <div className="field">
          <span>Условие</span>
          <div>
            {Object.keys(row.when).length === 0 ? (
              <span className="muted">иначе</span>
            ) : (
              describeWhen(def, row.when).map((w) => <div key={w}>{w}</div>)
            )}
          </div>
        </div>
        <label className="field">
          <span>Значение</span>
          <select className="select" value={value} onChange={(e) => setValue(e.target.value)}>
            {stepValues(def, step).map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Пункт документа</span>
          <input className="input" value={clause} maxLength={300} onChange={(e) => setClause(e.target.value)} />
        </label>
        <label className="field">
          <span>Пояснение</span>
          <input className="input" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />
        </label>
        <label className="field">
          <span>Основание правки</span>
          <input
            className="input"
            value={comment}
            maxLength={1000}
            required
            placeholder="Например: сверено с приложением к приказу"
            onChange={(e) => setComment(e.target.value)}
          />
          <small>Правка создаёт новую ревизию и снимает отметку о сверке.</small>
        </label>
      </form>
    </Modal>
  );
}

function SourceDialog({ table, onClose, onSaved }: { table: Table; onClose: () => void; onSaved: (t: Table) => void }) {
  const [src, setSrc] = useState<Source>({ ...table.source });
  const [version, setVersion] = useState(table.version);
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof Source, v: string) => setSrc((p) => ({ ...p, [k]: v }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const clean = Object.fromEntries(
      Object.entries(src).map(([k, v]) => [k, typeof v === "string" && v.trim() ? v.trim() : null]),
    );
    try {
      onSaved(
        await apiSend<Table>("PATCH", `/refs/classification-tables/${table.regime}`, {
          source: clean,
          version: version.trim(),
          comment: comment.trim(),
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось сохранить");
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Источник таблицы"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="submit"
            form="source-edit"
            className="btn btn-primary"
            disabled={busy || !comment.trim() || !src.document?.trim() || !version.trim()}
          >
            Сохранить
          </button>
        </>
      }
    >
      <form id="source-edit" className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <label className="field">
          <span>Документ</span>
          <input className="input" value={src.document ?? ""} required onChange={(e) => set("document", e.target.value)} />
        </label>
        <div className="form-row">
          <label className="field">
            <span>Пункт</span>
            <input className="input" value={src.clause ?? ""} onChange={(e) => set("clause", e.target.value)} />
          </label>
          <label className="field">
            <span>Приложение</span>
            <input className="input" value={src.appendix ?? ""} onChange={(e) => set("appendix", e.target.value)} />
          </label>
        </div>
        <label className="field">
          <span>Ссылка</span>
          <input className="input" value={src.url ?? ""} onChange={(e) => set("url", e.target.value)} />
        </label>
        <label className="field">
          <span>Примечание</span>
          <textarea className="textarea" rows={2} value={src.note ?? ""} onChange={(e) => set("note", e.target.value)} />
        </label>
        <label className="field">
          <span>Версия таблицы</span>
          <input className="input" value={version} maxLength={64} onChange={(e) => setVersion(e.target.value)} />
        </label>
        <label className="field">
          <span>Основание правки</span>
          <input className="input" value={comment} maxLength={1000} required onChange={(e) => setComment(e.target.value)} />
        </label>
      </form>
    </Modal>
  );
}
