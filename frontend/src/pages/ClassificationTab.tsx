import { ArrowLeft, ArrowRight, Calculator, CheckCheck, History, Save, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { ClassTrace } from "../components/ClassTrace";
import { Drawer } from "../components/Drawer";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { VerifyBadge } from "../components/VerifyBadge";
import { ApiError, apiGet, apiSend } from "../lib/api";
import { useAuth } from "../lib/auth";
import {
  ORIGIN_LABELS,
  STATUS_LABELS,
  STATUS_PILL,
  sourceText,
  valueLabel,
  wizardSteps,
  type Classification,
  type ClassificationDetail,
  type Outcome,
  type Table,
} from "../lib/classification";
import { formatDateTime } from "../lib/format";
import type { ObjectFull } from "../lib/objects";

export function ClassificationTab({
  obj,
  editable,
  onChanged,
}: {
  obj: ObjectFull;
  editable: boolean;
  onChanged: () => void;
}) {
  const { can, me } = useAuth();
  const [table, setTable] = useState<Table | null>(null);
  const [items, setItems] = useState<Classification[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [wizard, setWizard] = useState<Record<string, string> | null>(null);
  const [opened, setOpened] = useState<string | null>(null);

  const load = useCallback(() => {
    setError(null);
    if (!obj.regime) {
      setItems([]);
      return;
    }
    apiGet<Table>(`/refs/classification-tables/${obj.regime}`)
      .then(setTable)
      .catch((e: Error) => setError(e.message));
    apiGet<Classification[]>(`/objects/${obj.id}/classifications`)
      .then(setItems)
      .catch((e: Error) => setError(e.message));
  }, [obj.id, obj.regime]);

  useEffect(load, [load]);

  const reload = () => {
    load();
    onChanged();
  };

  if (!obj.regime) {
    return (
      <section className="card">
        <EmptyState
          icon={<Calculator size={21} />}
          title="Режим не выбран"
          text="Классификация проводится для ГИС, ИСПДн и КИИ. Укажите вид объекта и нормативный режим в описании."
        />
      </section>
    );
  }
  if (error && !items) return <ErrorAlert message={error} onRetry={load} />;
  if (!items || !table) return <Loading />;

  const relevant = items.filter((c) => c.regime === obj.regime);
  const approved = relevant.find((c) => c.status === "approved") ?? null;
  const draft = relevant.find((c) => c.status === "draft") ?? null;
  const canCompute = editable && can("classification.edit");
  const lastInputs = (draft ?? approved)?.inputs;

  return (
    <>
      {error && <ErrorAlert message={error} />}

      <div className="row-phi">
        <section className="card">
          <div className="card-head">
            <h2>{table.definition.result.label}</h2>
            {approved ? (
              <span className="pill pill-ok">Утверждена</span>
            ) : draft ? (
              <span className="pill pill-warn">Не утверждена</span>
            ) : (
              <span className="pill pill-muted">Не определена</span>
            )}
          </div>
          <div className="card-pad class-current">
            {approved || draft ? (
              <>
                <div className="class-result">{(approved ?? draft)!.result_label}</div>
                {approved ? (
                  <p className="muted">
                    Утвердил {approved.approved_by_name}, {formatDateTime(approved.approved_at)}
                    {approved.unverified_acknowledged && " · по несверенной таблице"}
                  </p>
                ) : (
                  <p className="muted">
                    Черновик от {formatDateTime(draft!.created_at)}, {draft!.created_by_name}. Ждёт утверждения.
                  </p>
                )}
                {approved && draft && (
                  <p className="muted">
                    Есть новый черновик: {draft.result_label}, ждёт утверждения.
                  </p>
                )}
              </>
            ) : (
              <p className="muted">Расчёта ещё не было.</p>
            )}
            <div className="actions">
              {canCompute && !wizard && (
                <button type="button" className="btn btn-primary" onClick={() => setWizard({ ...(lastInputs ?? {}) })}>
                  <Calculator size={15} /> {approved || draft ? "Новый расчёт" : "Определить"}
                </button>
              )}
              {draft && (
                <button type="button" className="btn" onClick={() => setOpened(draft.id)}>
                  <ShieldCheck size={15} /> Черновик
                </button>
              )}
            </div>
          </div>
        </section>

        <section className="card">
          <div className="card-head">
            <h2>Таблица</h2>
            <VerifyBadge verified={table.verified} by={table.verified_by_name} at={table.verified_at} />
          </div>
          <dl className="props card-pad">
            <dt>Документ</dt>
            <dd>{sourceText(table.source) || "—"}</dd>
            <dt>Версия</dt>
            <dd>
              {table.version} <span className="muted">· ревизия {table.revision}</span>
            </dd>
            <dt>Происхождение</dt>
            <dd>{ORIGIN_LABELS[table.origin] ?? table.origin}</dd>
          </dl>
          {table.source.note && <p className="card-pad cell-sub table-note">{table.source.note}</p>}
          <div className="card-pad">
            <Link to={`/refs/classification?regime=${table.regime}`}>Открыть таблицу в справочнике</Link>
          </div>
        </section>
      </div>

      {wizard && (
        <Wizard
          obj={obj}
          table={table}
          initial={wizard}
          onCancel={() => setWizard(null)}
          onSaved={(c) => {
            setWizard(null);
            reload();
            setOpened(c.id);
          }}
        />
      )}

      <section className="card">
        <div className="card-head">
          <h2>
            <History size={16} /> История расчётов
          </h2>
          <span className="count">{items.length}</span>
        </div>
        {items.length === 0 ? (
          <p className="card-pad muted">Пусто</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Дата</th>
                  <th>Результат</th>
                  <th>Статус</th>
                  <th>Таблица</th>
                  <th>Рассчитал</th>
                  <th>Утвердил</th>
                </tr>
              </thead>
              <tbody>
                {items.map((c) => (
                  <tr
                    key={c.id}
                    className={`clickable${opened === c.id ? " selected" : ""}`}
                    onClick={() => setOpened(c.id)}
                  >
                    <td className="nowrap">
                      <button type="button" className="link-btn" onClick={() => setOpened(c.id)}>
                        {formatDateTime(c.created_at)}
                      </button>
                    </td>
                    <td className="cell-title">{c.result_label}</td>
                    <td>
                      <span className={`pill ${STATUS_PILL[c.status]}`}>{STATUS_LABELS[c.status]}</span>
                    </td>
                    <td className="nowrap">
                      {c.table_version} · рев. {c.table_revision}
                      {c.table_changed && c.status === "draft" && (
                        <div className="cell-sub">таблица изменена</div>
                      )}
                    </td>
                    <td>{c.created_by_name ?? "—"}</td>
                    <td>{c.approved_by_name ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {opened && (
        <ClassificationDrawer
          key={opened}
          id={opened}
          editable={editable}
          myId={me?.id ?? null}
          canApprove={can("approve")}
          onClose={() => setOpened(null)}
          onApproved={reload}
        />
      )}
    </>
  );
}

// ---------- Мастер ----------

function Wizard({
  obj,
  table,
  initial,
  onCancel,
  onSaved,
}: {
  obj: ObjectFull;
  table: Table;
  initial: Record<string, string>;
  onCancel: () => void;
  onSaved: (c: ClassificationDetail) => void;
}) {
  const def = table.definition;
  const steps = useMemo(() => wizardSteps(def), [def]);
  // Значения, которых нет в текущей таблице (её исправили), не переносим.
  const [inputs, setInputs] = useState<Record<string, string>>(() =>
    Object.fromEntries(
      def.inputs
        .filter((i) => i.options.some((o) => o.value === initial[i.key]))
        .map((i) => [i.key, initial[i.key] ?? ""]),
    ),
  );
  const [step, setStep] = useState(0);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [justification, setJustification] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const isResult = step === steps.length;
  const current = steps[step];
  const stepDone = (i: number) => (steps[i]?.inputs ?? []).every((x) => inputs[x.key]);

  useEffect(() => {
    if (!isResult) return;
    setOutcome(null);
    setError(null);
    apiSend<Outcome>("POST", `/objects/${obj.id}/classifications/preview`, { inputs })
      .then(setOutcome)
      .catch((e: Error) => setError(e.message));
  }, [isResult, inputs, obj.id]);

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onSaved(
        await apiSend<ClassificationDetail>("POST", `/objects/${obj.id}/classifications`, {
          inputs,
          justification: justification.trim() || null,
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось сохранить");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card" aria-label="Мастер классификации">
      <div className="card-head">
        <h2>Мастер: {def.result.label.toLowerCase()}</h2>
        <button type="button" className="btn btn-sm btn-ghost" onClick={onCancel}>
          Отмена
        </button>
      </div>
      <ol className="stepper">
        {steps.map((s, i) => (
          <li key={s.key} aria-current={i === step ? "step" : undefined} className={stepDone(i) ? "done" : undefined}>
            <button type="button" className="link-btn" onClick={() => setStep(i)}>
              <span className="trace-num">{i + 1}</span> {s.title}
            </button>
          </li>
        ))}
        <li aria-current={isResult ? "step" : undefined}>
          <button
            type="button"
            className="link-btn"
            disabled={!steps.every((_, i) => stepDone(i))}
            onClick={() => setStep(steps.length)}
          >
            <span className="trace-num">{steps.length + 1}</span> Результат
          </button>
        </li>
      </ol>

      {!isResult && current && (
        <div className="card-pad form-stack">
          {current.inputs.map((inp) => (
            <fieldset key={inp.key} className="field">
              <legend className="field-legend">{inp.label}</legend>
              {inp.help && <small>{inp.help}</small>}
              <div className="option-grid">
                {inp.options.map((o) => (
                  <label key={o.value} className={`check option${inputs[inp.key] === o.value ? " checked" : ""}`}>
                    <input
                      type="radio"
                      name={inp.key}
                      value={o.value}
                      checked={inputs[inp.key] === o.value}
                      onChange={() => setInputs((prev) => ({ ...prev, [inp.key]: o.value }))}
                    />
                    <span>
                      <b>{o.label}</b>
                      {o.help && <small>{o.help}</small>}
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>
          ))}
          <div className="actions">
            <button type="button" className="btn" disabled={step === 0} onClick={() => setStep(step - 1)}>
              <ArrowLeft size={15} /> Назад
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={!stepDone(step)}
              onClick={() => setStep(step + 1)}
            >
              Далее <ArrowRight size={15} />
            </button>
          </div>
        </div>
      )}

      {isResult && (
        <form className="card-pad form-stack" onSubmit={save}>
          {error && <ErrorAlert message={error} />}
          {!outcome && !error && <Loading />}
          {outcome && (
            <>
              <div className="class-outcome">
                <span className="muted">{def.result.label}</span>
                <div className="class-result">{outcome.result_label}</div>
                {!outcome.table_verified && (
                  <span className="pill pill-warn">Таблица требует сверки — результат предварительный</span>
                )}
              </div>
              <ClassTrace definition={def} trace={outcome.trace} inputs={inputs} tableSource={outcome.table_source} />
              <label className="field">
                <span>Обоснование</span>
                <textarea
                  className="textarea"
                  rows={3}
                  value={justification}
                  maxLength={10000}
                  placeholder="На чём основаны исходные данные: письма заказчика, перечень сведений, модель угроз…"
                  onChange={(e) => setJustification(e.target.value)}
                />
                <small>Попадёт в акт классификации вместе с таблицей и сработавшими строками.</small>
              </label>
              <div className="actions">
                <button type="button" className="btn" onClick={() => setStep(steps.length - 1)}>
                  <ArrowLeft size={15} /> Назад
                </button>
                <button type="submit" className="btn btn-primary" disabled={busy}>
                  <Save size={15} /> Сохранить черновик
                </button>
              </div>
            </>
          )}
        </form>
      )}
    </section>
  );
}

// ---------- Карточка расчёта и утверждение ----------

function ClassificationDrawer({
  id,
  editable,
  myId,
  canApprove,
  onClose,
  onApproved,
}: {
  id: string;
  editable: boolean;
  myId: string | null;
  canApprove: boolean;
  onClose: () => void;
  onApproved: () => void;
}) {
  const [c, setC] = useState<ClassificationDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [approving, setApproving] = useState(false);

  useEffect(() => {
    apiGet<ClassificationDetail>(`/classifications/${id}`)
      .then(setC)
      .catch((e: Error) => setError(e.message));
  }, [id]);

  const own = c !== null && c.created_by === myId;
  const blocked = c?.table_changed
    ? "Таблица изменилась после расчёта — нужен новый расчёт"
    : own
      ? "Нельзя утвердить собственный расчёт"
      : null;

  return (
    <Drawer
      title={c ? c.result_label : "Расчёт"}
      onClose={onClose}
      footer={
        c?.status === "draft" && canApprove && editable ? (
          <>
            {blocked && <span className="cell-sub drawer-note">{blocked}</span>}
            <button
              type="button"
              className="btn btn-primary"
              disabled={blocked !== null}
              title={blocked ?? undefined}
              onClick={() => setApproving(true)}
            >
              <CheckCheck size={15} /> Утвердить
            </button>
          </>
        ) : undefined
      }
    >
      {error && <ErrorAlert message={error} />}
      {!c && !error && <Loading />}
      {c && (
        <>
          <div className="drawer-section">
            <dl className="props">
              <dt>Статус</dt>
              <dd>
                <span className={`pill ${STATUS_PILL[c.status]}`}>{STATUS_LABELS[c.status]}</span>
              </dd>
              <dt>Рассчитан</dt>
              <dd>
                {formatDateTime(c.created_at)}, {c.created_by_name}
              </dd>
              {c.approved_at && (
                <>
                  <dt>Утверждён</dt>
                  <dd>
                    {formatDateTime(c.approved_at)}, {c.approved_by_name}
                    {c.approval_comment && <div className="cell-sub">{c.approval_comment}</div>}
                  </dd>
                </>
              )}
              <dt>Таблица</dt>
              <dd>
                {c.table_version} · ревизия {c.table_revision}{" "}
                {c.table_verified ? (
                  <span className="pill pill-ok">Сверена</span>
                ) : (
                  <span className="pill pill-warn">Требовала сверки</span>
                )}
              </dd>
              <dt>Воспроизводимость</dt>
              <dd>
                {c.reproducible ? (
                  <span className="pill pill-ok">Пересчёт по снимку таблицы совпадает</span>
                ) : (
                  <span className="pill pill-danger">Не воспроизводится</span>
                )}
              </dd>
            </dl>
            {c.table_changed && c.status !== "superseded" && (
              <div className="alert alert-warn">
                <span className="alert-text">
                  Таблица классификации изменилась после этого расчёта. Результат показан по снимку таблицы на
                  момент расчёта.
                </span>
              </div>
            )}
          </div>

          <div className="drawer-section">
            <h3>Исходные данные</h3>
            <dl className="props">
              {c.table_snapshot.inputs.map((i) => (
                <div key={i.key} className="props-row">
                  <dt>{i.label}</dt>
                  <dd>{valueLabel(c.table_snapshot, i.key, c.inputs[i.key] ?? "")}</dd>
                </div>
              ))}
            </dl>
          </div>

          {c.justification && (
            <div className="drawer-section">
              <h3>Обоснование</h3>
              <p className="prewrap">{c.justification}</p>
            </div>
          )}

          <div className="drawer-section">
            <h3>Как получен результат</h3>
            <ClassTrace definition={c.table_snapshot} trace={c.trace} inputs={c.inputs} tableSource={c.table_source} />
          </div>
        </>
      )}

      {approving && c && (
        <ApproveDialog
          c={c}
          onClose={() => setApproving(false)}
          onDone={(next) => {
            setApproving(false);
            setC(next);
            onApproved();
          }}
        />
      )}
    </Drawer>
  );
}

function ApproveDialog({
  c,
  onClose,
  onDone,
}: {
  c: ClassificationDetail;
  onClose: () => void;
  onDone: (c: ClassificationDetail) => void;
}) {
  const [comment, setComment] = useState("");
  const [ack, setAck] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const needAck = !c.table_verified;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onDone(
        await apiSend<ClassificationDetail>("POST", `/classifications/${c.id}/approve`, {
          comment: comment.trim() || null,
          acknowledge_unverified: ack,
        }),
      );
    } catch (err) {
      setError(err instanceof ApiError || err instanceof Error ? err.message : "Не удалось утвердить");
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Утвердить классификацию"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="submit"
            form="approve-class"
            className="btn btn-primary"
            disabled={busy || (needAck && !ack)}
          >
            Утвердить
          </button>
        </>
      }
    >
      <form id="approve-class" className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <p>
          Результат: <b>{c.result_label}</b>. Утверждение фиксируется в журнале аудита; прежняя утверждённая
          классификация объекта станет заменённой и останется в истории.
        </p>
        {needAck && (
          <label className="check">
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
            <span>
              <b>Утверждаю по несверенной таблице</b>
              <small>
                Таблица классификации ещё не сверена методистом с официальным текстом. В документах результат будет
                помечен как основанный на несверенных данных.
              </small>
            </span>
          </label>
        )}
        <label className="field">
          <span>Комментарий</span>
          <textarea className="textarea" rows={2} maxLength={2000} value={comment} onChange={(e) => setComment(e.target.value)} />
        </label>
      </form>
    </Modal>
  );
}
