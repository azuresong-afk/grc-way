import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  CheckCheck,
  FilePlus2,
  History,
  Plus,
  Save,
  Search,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { Drawer } from "../components/Drawer";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { apiGet, apiSend } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDateTime, formatNumber } from "../lib/format";
import type { Host, ObjectFull } from "../lib/objects";
import {
  LINK_TITLES,
  STATUS_LABELS,
  STATUS_PILL,
  STEP_HELP,
  ciaText,
  nextObjectKey,
  suggestLinks,
  type Candidate,
  type DataStep,
  type ImpactObject,
  type IntruderItem,
  type LinkKey,
  type MethodItem,
  type ModelBrief,
  type ModelDetail,
  type ModelThreat,
  type ScenarioItem,
  type StepKey,
  type Steps,
} from "../lib/threatModel";
import type { ThreatItem, ThreatRefs } from "../lib/threats";

/** Справочник Методики, разложенный для мастера. */
interface RefIndex {
  byCode: Map<string, ThreatItem>;
  ofKind: (kind: ThreatItem["kind"]) => ThreatItem[];
  children: (code: string) => ThreatItem[];
  title: (code: string) => string;
}

function indexRefs(refs: ThreatRefs): RefIndex {
  const byCode = new Map(refs.items.map((i) => [i.code, i]));
  return {
    byCode,
    ofKind: (kind) => refs.items.filter((i) => i.kind === kind),
    children: (code) => refs.items.filter((i) => i.parent_code === code),
    title: (code) => byCode.get(code)?.title ?? code,
  };
}

const RESULT = "result" as const;
type View = StepKey | typeof RESULT;

export function ThreatModelTab({ obj, editable }: { obj: ObjectFull; editable: boolean }) {
  const { can, me } = useAuth();
  const [list, setList] = useState<ModelBrief[] | null>(null);
  const [model, setModel] = useState<ModelDetail | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [refs, setRefs] = useState<RefIndex | null>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<View>("consequences");
  const [approving, setApproving] = useState(false);

  const loadList = useCallback(() => {
    apiGet<ModelBrief[]>(`/objects/${obj.id}/threat-models`)
      .then((rows) => {
        setList(rows);
        setSelected((cur) => {
          if (cur && rows.some((r) => r.id === cur)) return cur;
          const pick = rows.find((r) => r.status === "draft") ?? rows.find((r) => r.status === "approved") ?? rows[0];
          return pick?.id ?? null;
        });
      })
      .catch((e: Error) => setError(e.message));
  }, [obj.id]);

  useEffect(() => {
    loadList();
    apiGet<ThreatRefs>("/refs/threats")
      .then((r) => setRefs(indexRefs(r)))
      .catch((e: Error) => setError(e.message));
    apiGet<Host[]>(`/objects/${obj.id}/hosts`)
      .then(setHosts)
      .catch(() => setHosts([]));
  }, [loadList, obj.id]);

  useEffect(() => {
    if (!selected) {
      setModel(null);
      return;
    }
    apiGet<ModelDetail>(`/threat-models/${selected}`)
      .then(setModel)
      .catch((e: Error) => setError(e.message));
  }, [selected]);

  const accept = (m: ModelDetail) => {
    setModel(m);
    setList((rows) => rows?.map((r) => (r.id === m.id ? { ...r, ...m } : r)) ?? rows);
  };

  async function create() {
    setBusy(true);
    setError(null);
    try {
      const m = await apiSend<ModelDetail>("POST", `/objects/${obj.id}/threat-models`);
      setSelected(m.id);
      setModel(m);
      setView("consequences");
      loadList();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось создать");
    } finally {
      setBusy(false);
    }
  }

  async function discard() {
    if (!model) return;
    setBusy(true);
    try {
      await apiSend("DELETE", `/threat-models/${model.id}`);
      setSelected(null);
      loadList();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось удалить");
    } finally {
      setBusy(false);
    }
  }

  if (error && !list) return <ErrorAlert message={error} onRetry={loadList} />;
  if (!list || !refs) return <Loading />;

  const canEdit = editable && can("threats.edit");
  const hasDraft = list.some((m) => m.status === "draft");
  const approved = list.find((m) => m.status === "approved") ?? null;

  if (list.length === 0) {
    return (
      <section className="card">
        {error && <ErrorAlert message={error} />}
        <EmptyState
          icon={<ShieldAlert size={21} />}
          title="Модели угроз нет"
          text="Мастер проведёт по шагам Методики оценки угроз 2021: последствия, объекты воздействия, нарушители, способы, сценарии и угрозы из БДУ."
          action={
            canEdit ? (
              <button type="button" className="btn btn-primary" disabled={busy} onClick={create}>
                <FilePlus2 size={15} /> Составить модель угроз
              </button>
            ) : undefined
          }
        />
      </section>
    );
  }

  const readOnly = !canEdit || model?.status !== "draft";
  const own = model !== null && me !== null && (model.created_by === me.id || model.editor_ids.includes(me.id));

  return (
    <>
      {error && <ErrorAlert message={error} />}

      <div className="row-phi">
        <section className="card">
          <div className="card-head">
            <h2>Модель угроз{model ? ` · версия ${model.version}` : ""}</h2>
            {model && <span className={`pill ${STATUS_PILL[model.status]}`}>{STATUS_LABELS[model.status]}</span>}
          </div>
          {!model ? (
            <Loading />
          ) : (
            <div className="card-pad tm-summary">
              <div className="tm-kpis">
                <div>
                  <span className="kpi-label">Шагов заполнено</span>
                  <div className="kpi-value">
                    {model.progress.done} <span className="muted">из {model.progress.total}</span>
                  </div>
                </div>
                <div>
                  <span className="kpi-label">Актуальных угроз</span>
                  <div className="kpi-value">
                    {model.relevant} <span className="muted">из {model.considered}</span>
                  </div>
                </div>
              </div>
              <div
                className="impl-bar"
                role="progressbar"
                aria-label="Заполнение шагов"
                aria-valuemin={0}
                aria-valuemax={model.progress.total}
                aria-valuenow={model.progress.done}
              >
                <span
                  className="impl-bar-implemented"
                  style={{ width: `${(model.progress.done / model.progress.total) * 100}%` }}
                />
              </div>
              <p className="muted">
                {model.status === "approved" || model.status === "superseded"
                  ? `Утвердил ${model.approved_by_name}, ${formatDateTime(model.approved_at)}${model.unverified_acknowledged ? " · по несверенному справочнику" : ""}`
                  : `Составляет ${model.created_by_name ?? "—"} с ${formatDateTime(model.created_at)}; правок: ${model.edits}`}
              </p>
              <div className="actions">
                {canEdit && !hasDraft && (
                  <button type="button" className="btn btn-primary" disabled={busy} onClick={create}>
                    <FilePlus2 size={15} /> Новая версия
                  </button>
                )}
                {model.status !== "draft" && hasDraft && (
                  <button
                    type="button"
                    className="btn"
                    onClick={() => setSelected(list.find((m) => m.status === "draft")!.id)}
                  >
                    Открыть черновик
                  </button>
                )}
                {model.status === "draft" && approved && (
                  <button type="button" className="btn" onClick={() => setSelected(approved.id)}>
                    Утверждённая версия {approved.version}
                  </button>
                )}
                {model.status === "draft" && canEdit && (
                  <button type="button" className="btn btn-ghost" disabled={busy} onClick={discard}>
                    <Trash2 size={15} /> Удалить черновик
                  </button>
                )}
              </div>
            </div>
          )}
        </section>

        <section className="card">
          <div className="card-head">
            <h2>Исходные данные</h2>
          </div>
          <dl className="props card-pad">
            <dt>Методика</dt>
            <dd>
              {model && model.unverified_refs.length > 0 ? (
                <span className="pill pill-warn">Требуют сверки: {model.unverified_refs.length}</span>
              ) : (
                <span className="pill pill-ok">Используемые записи сверены</span>
              )}
              <div className="cell-sub">
                <Link to="/refs/threats">Справочник Методики оценки угроз</Link>
              </div>
            </dd>
            <dt>БДУ</dt>
            <dd>
              {model?.bdu_version ? `выгрузка от ${model.bdu_version}` : "версия выгрузки не указана"}
              <div className="cell-sub">
                <Link to="/refs/bdu">Угрозы БДУ ФСТЭК России</Link>
              </div>
            </dd>
            <dt>Хостов объекта</dt>
            <dd>{formatNumber(hosts.length)}</dd>
          </dl>
        </section>
      </div>

      {model && (
        <section className="card" aria-label="Мастер модели угроз">
          <ol className="stepper">
            {model.progress.steps.map((s, i) => (
              <li
                key={s.key}
                aria-current={view === s.key ? "step" : undefined}
                className={s.done && !s.problems.length ? "done" : undefined}
              >
                <button type="button" className="link-btn" onClick={() => setView(s.key)}>
                  <span className="trace-num">{i + 1}</span> {s.title}
                  {s.problems.length > 0 && (
                    <span className="count count-warn" title={s.problems.join("\n")}>
                      {s.problems.length}
                    </span>
                  )}
                </button>
              </li>
            ))}
            <li aria-current={view === RESULT ? "step" : undefined} className={model.progress.ready ? "done" : undefined}>
              <button type="button" className="link-btn" onClick={() => setView(RESULT)}>
                <span className="trace-num">{model.progress.steps.length + 1}</span> Итог
              </button>
            </li>
          </ol>
          <StepBody
            key={`${model.id}-${view}`}
            view={view}
            model={model}
            refs={refs}
            hosts={hosts}
            readOnly={readOnly}
            onSaved={accept}
            onNavigate={setView}
            onApprove={
              model.status === "draft" && editable && can("approve") ? () => setApproving(true) : undefined
            }
            approveBlocked={
              own ? "Нельзя утвердить модель, которую вы составляли или правили" : !model.progress.ready ? "Есть незаполненные шаги или проблемы" : null
            }
          />
        </section>
      )}

      <section className="card">
        <div className="card-head">
          <h2>
            <History size={16} /> Версии
          </h2>
          <span className="count">{list.length}</span>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Версия</th>
                <th>Статус</th>
                <th>Актуальных угроз</th>
                <th>Составил</th>
                <th>Утвердил</th>
              </tr>
            </thead>
            <tbody>
              {list.map((m) => (
                <tr
                  key={m.id}
                  className={`clickable${selected === m.id ? " selected" : ""}`}
                  onClick={() => setSelected(m.id)}
                >
                  <td className="nowrap">
                    <button type="button" className="link-btn" onClick={() => setSelected(m.id)}>
                      Версия {m.version}
                    </button>
                    <div className="cell-sub">{formatDateTime(m.created_at)}</div>
                  </td>
                  <td>
                    <span className={`pill ${STATUS_PILL[m.status]}`}>{STATUS_LABELS[m.status]}</span>
                  </td>
                  <td className="nowrap">
                    {m.relevant} <span className="muted">из {m.considered}</span>
                  </td>
                  <td>{m.created_by_name ?? "—"}</td>
                  <td>
                    {m.approved_by_name ?? "—"}
                    {m.approved_at && <div className="cell-sub">{formatDateTime(m.approved_at)}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {approving && model && (
        <ApproveDialog
          model={model}
          onClose={() => setApproving(false)}
          onDone={(m) => {
            setApproving(false);
            setModel(m);
            loadList();
          }}
        />
      )}
    </>
  );
}

// ---------- Шаги ----------

interface StepProps {
  model: ModelDetail;
  refs: RefIndex;
  hosts: Host[];
  readOnly: boolean;
  onSaved: (m: ModelDetail) => void;
}

function StepBody({
  view,
  onNavigate,
  onApprove,
  approveBlocked,
  ...props
}: StepProps & {
  view: View;
  onNavigate: (v: View) => void;
  onApprove?: () => void;
  approveBlocked: string | null;
}) {
  const order: View[] = [...props.model.progress.steps.map((s) => s.key), RESULT];
  const idx = order.indexOf(view);
  const nav = (
    <>
      <button type="button" className="btn" disabled={idx === 0} onClick={() => onNavigate(order[idx - 1]!)}>
        <ArrowLeft size={15} /> Назад
      </button>
      {idx < order.length - 1 && (
        <button type="button" className="btn" onClick={() => onNavigate(order[idx + 1]!)}>
          Далее <ArrowRight size={15} />
        </button>
      )}
    </>
  );
  const step = props.model.progress.steps.find((s) => s.key === view);
  return (
    <div className="card-pad form-stack">
      {view !== RESULT && <p className="muted tm-help">{STEP_HELP[view]}</p>}
      {step && step.problems.length > 0 && <Problems items={step.problems} />}
      {view === "consequences" && <ConsequencesStep {...props} nav={nav} />}
      {view === "objects" && <ObjectsStep {...props} nav={nav} />}
      {view === "intruders" && <IntrudersStep {...props} nav={nav} />}
      {view === "methods" && <MethodsStep {...props} nav={nav} />}
      {view === "scenarios" && <ScenariosStep {...props} nav={nav} />}
      {view === "threats" && <ThreatsStep {...props} nav={nav} />}
      {view === RESULT && (
        <ResultStep {...props} nav={nav} onApprove={onApprove} approveBlocked={approveBlocked} onNavigate={onNavigate} />
      )}
    </div>
  );
}

function Problems({ items }: { items: string[] }) {
  return (
    <div className="alert alert-warn">
      <span className="alert-text">
        <AlertTriangle size={14} /> {items.length === 1 ? items[0] : `Проблем: ${items.length}`}
        {items.length > 1 && (
          <ul className="tm-problems">
            {items.slice(0, 12).map((p) => (
              <li key={p}>{p}</li>
            ))}
            {items.length > 12 && <li>… и ещё {items.length - 12}</li>}
          </ul>
        )}
      </span>
    </div>
  );
}

/** Сохранение шага 1–5 целиком; кнопка показывает, есть ли несохранённые правки. */
function useStepSave<T>(model: ModelDetail, step: DataStep, initial: T, onSaved: (m: ModelDetail) => void) {
  const [data, setData] = useState<T>(initial);
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const change = (next: T | ((prev: T) => T)) => {
    setData(next);
    setDirty(true);
  };
  async function save() {
    setBusy(true);
    setError(null);
    try {
      onSaved(await apiSend<ModelDetail>("PUT", `/threat-models/${model.id}/steps/${step}`, { data }));
      setDirty(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось сохранить");
    } finally {
      setBusy(false);
    }
  }
  return { data, change, dirty, error, busy, save };
}

function StepActions({
  nav,
  readOnly,
  dirty,
  busy,
  error,
  onSave,
}: {
  nav: ReactNode;
  readOnly: boolean;
  dirty: boolean;
  busy: boolean;
  error: string | null;
  onSave: () => void;
}) {
  return (
    <>
      {error && <ErrorAlert message={error} />}
      <div className="actions">
        {nav}
        {!readOnly && (
          <button type="button" className="btn btn-primary" disabled={busy || !dirty} onClick={onSave}>
            <Save size={15} /> {dirty ? "Сохранить шаг" : "Сохранено"}
          </button>
        )}
      </div>
    </>
  );
}

function toggle(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter((x) => x !== value) : [...list, value];
}

function ChipPick({
  label,
  options,
  value,
  disabled,
  onChange,
}: {
  label: string;
  options: { value: string; label: string; title?: string }[];
  value: string[];
  disabled: boolean;
  onChange: (v: string[]) => void;
}) {
  return (
    <div className="field">
      <span>{label}</span>
      {options.length === 0 ? (
        <small>Нечего выбрать — заполните предыдущие шаги.</small>
      ) : (
        <div className="chips" role="group" aria-label={label}>
          {options.map((o) => (
            <button
              key={o.value}
              type="button"
              className="chip"
              title={o.title}
              aria-pressed={value.includes(o.value)}
              disabled={disabled}
              onClick={() => onChange(toggle(value, o.value))}
            >
              {o.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

type Nav = { nav: ReactNode };

// 1. Негативные последствия.
function ConsequencesStep({ model, refs, readOnly, onSaved, nav }: StepProps & Nav) {
  const s = useStepSave(model, "consequences", model.steps.consequences, onSaved);
  const chosen = new Map(s.data.items.map((i) => [i.code, i]));
  const set = (code: string, on: boolean) =>
    s.change((d) => ({
      ...d,
      items: on ? [...d.items, { code, justification: "" }] : d.items.filter((i) => i.code !== code),
    }));
  const justify = (code: string, text: string) =>
    s.change((d) => ({ ...d, items: d.items.map((i) => (i.code === code ? { ...i, justification: text } : i)) }));
  return (
    <>
      {refs.ofKind("consequence_type").map((t) => (
        <fieldset key={t.code} className="field tm-group">
          <legend className="field-legend">
            <span className="tag">{t.code}</span> {t.title}
          </legend>
          {refs.children(t.code).map((c) => {
            const item = chosen.get(c.code);
            return (
              <div key={c.code} className="tm-check-row">
                <label className="check">
                  <input
                    type="checkbox"
                    checked={!!item}
                    disabled={readOnly}
                    onChange={(e) => set(c.code, e.target.checked)}
                  />
                  <span>
                    <b>
                      <span className="muted">{c.code}</span> {c.title}
                    </b>
                  </span>
                </label>
                {item && (
                  <input
                    className="input"
                    aria-label={`Обоснование ${c.code}`}
                    placeholder="Почему последствие возможно для системы"
                    maxLength={4000}
                    value={item.justification ?? ""}
                    disabled={readOnly}
                    onChange={(e) => justify(c.code, e.target.value)}
                  />
                )}
              </div>
            );
          })}
        </fieldset>
      ))}
      <StepActions nav={nav} readOnly={readOnly} dirty={s.dirty} busy={s.busy} error={s.error} onSave={s.save} />
    </>
  );
}

// 2. Объекты воздействия.
function ObjectsStep({ model, refs, hosts, readOnly, onSaved, nav }: StepProps & Nav) {
  const s = useStepSave(model, "objects", model.steps.objects, onSaved);
  const cons = model.steps.consequences.items.map((c) => c.code);
  const patch = (key: string, p: Partial<ImpactObject>) =>
    s.change((d) => ({ ...d, items: d.items.map((o) => (o.key === key ? { ...o, ...p } : o)) }));
  const add = () =>
    s.change((d) => ({
      ...d,
      items: [...d.items, { key: nextObjectKey(d.items), name: "", hosts: [], impacts: [], consequences: [] }],
    }));
  const remove = (key: string) => s.change((d) => ({ ...d, items: d.items.filter((o) => o.key !== key) }));
  return (
    <>
      {s.data.items.length === 0 && <p className="muted">Объектов воздействия пока нет.</p>}
      {s.data.items.map((o, n) => (
        <div key={o.key} className="tm-block">
          <div className="tm-block-head">
            <span className="trace-num">{n + 1}</span>
            <input
              className="input"
              aria-label="Наименование объекта воздействия"
              placeholder="Например: СУБД с персональными данными"
              maxLength={300}
              value={o.name}
              disabled={readOnly}
              onChange={(e) => patch(o.key, { name: e.target.value })}
            />
            {!readOnly && (
              <button type="button" className="icon-btn" aria-label="Удалить объект" onClick={() => remove(o.key)}>
                <Trash2 size={15} />
              </button>
            )}
          </div>
          <input
            className="input"
            aria-label="Описание объекта воздействия"
            placeholder="Описание, размещение"
            maxLength={4000}
            value={o.description ?? ""}
            disabled={readOnly}
            onChange={(e) => patch(o.key, { description: e.target.value })}
          />
          <ChipPick
            label="Хосты объекта"
            options={hosts.map((h) => ({ value: h.address, label: h.hostname ? `${h.address} · ${h.hostname}` : h.address }))}
            value={o.hosts}
            disabled={readOnly}
            onChange={(v) => patch(o.key, { hosts: v })}
          />
          <fieldset className="field">
            <legend className="field-legend">Виды воздействия</legend>
            {refs.ofKind("impact").map((i) => (
              <label key={i.code} className="check">
                <input
                  type="checkbox"
                  checked={o.impacts.includes(i.code)}
                  disabled={readOnly}
                  onChange={() => patch(o.key, { impacts: toggle(o.impacts, i.code) })}
                />
                <span>
                  <span className="muted">{i.code}</span> {i.title}
                </span>
              </label>
            ))}
          </fieldset>
          <ChipPick
            label="Ведёт к последствиям (шаг 1)"
            options={cons.map((c) => ({ value: c, label: c, title: refs.title(c) }))}
            value={o.consequences}
            disabled={readOnly}
            onChange={(v) => patch(o.key, { consequences: v })}
          />
        </div>
      ))}
      {!readOnly && (
        <div>
          <button type="button" className="btn btn-sm" onClick={add}>
            <Plus size={14} /> Объект воздействия
          </button>
        </div>
      )}
      <StepActions nav={nav} readOnly={readOnly} dirty={s.dirty} busy={s.busy} error={s.error} onSave={s.save} />
    </>
  );
}

// 3. Нарушители.
function IntrudersStep({ model, refs, readOnly, onSaved, nav }: StepProps & Nav) {
  const s = useStepSave(model, "intruders", model.steps.intruders, onSaved);
  const byCode = new Map(s.data.items.map((i) => [i.code, i]));
  const caps = refs.ofKind("capability");
  const set = (code: string, p: Partial<IntruderItem> | null) =>
    s.change((d) => {
      if (p === null) return { ...d, items: d.items.filter((i) => i.code !== code) };
      const cur = d.items.find((i) => i.code === code);
      const next = { code, relevant: false, ...cur, ...p } as IntruderItem;
      return { ...d, items: cur ? d.items.map((i) => (i.code === code ? next : i)) : [...d.items, next] };
    });
  return (
    <>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Вид нарушителя</th>
              <th>Решение</th>
              <th>Возможности</th>
              <th>Обоснование</th>
            </tr>
          </thead>
          <tbody>
            {refs.ofKind("intruder").map((r) => {
              const item = byCode.get(r.code);
              const decision = item ? (item.relevant ? "yes" : "no") : "";
              return (
                <tr key={r.code}>
                  <td>
                    <span className="tag">{r.code}</span> {r.title}
                    <div className="cell-sub">
                      {r.attrs.category ?? "—"} · типовой уровень {r.attrs.capability ?? "—"}
                    </div>
                  </td>
                  <td>
                    <select
                      className="input"
                      aria-label={`Решение ${r.code}`}
                      value={decision}
                      disabled={readOnly}
                      onChange={(e) => {
                        const v = e.target.value;
                        if (!v) set(r.code, null);
                        else
                          set(r.code, {
                            relevant: v === "yes",
                            capability: v === "yes" ? (item?.capability ?? r.attrs.capability) : item?.capability,
                          });
                      }}
                    >
                      <option value="">Не рассмотрен</option>
                      <option value="yes">Актуален</option>
                      <option value="no">Не актуален</option>
                    </select>
                  </td>
                  <td>
                    <select
                      className="input"
                      aria-label={`Возможности ${r.code}`}
                      value={item?.capability ?? ""}
                      disabled={readOnly || !item?.relevant}
                      onChange={(e) => set(r.code, { capability: e.target.value || undefined })}
                    >
                      <option value="">—</option>
                      {caps.map((c) => (
                        <option key={c.code} value={c.code} title={c.title}>
                          {c.code}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <input
                      className="input"
                      aria-label={`Обоснование ${r.code}`}
                      maxLength={4000}
                      value={item?.justification ?? ""}
                      disabled={readOnly || !item}
                      placeholder={item ? "Почему актуален / не актуален" : ""}
                      onChange={(e) => set(r.code, { justification: e.target.value })}
                    />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <StepActions nav={nav} readOnly={readOnly} dirty={s.dirty} busy={s.busy} error={s.error} onSave={s.save} />
    </>
  );
}

// 4. Способы и интерфейсы.
function MethodsStep({ model, refs, readOnly, onSaved, nav }: StepProps & Nav) {
  const s = useStepSave(model, "methods", model.steps.methods, onSaved);
  const objects = model.steps.objects.items;
  const actual = model.steps.intruders.items.filter((i) => i.relevant).map((i) => i.code);
  const byCode = new Map(s.data.items.map((i) => [i.code, i]));
  const set = (code: string, p: Partial<MethodItem> | null) =>
    s.change((d) => {
      if (p === null) return { ...d, items: d.items.filter((i) => i.code !== code) };
      const cur = d.items.find((i) => i.code === code);
      const next = { code, objects: [], intruders: [], ...cur, ...p } as MethodItem;
      return { ...d, items: cur ? d.items.map((i) => (i.code === code ? next : i)) : [...d.items, next] };
    });
  return (
    <>
      {refs.ofKind("method").map((r) => {
        const item = byCode.get(r.code);
        return (
          <div key={r.code} className={`tm-block${item ? "" : " tm-block-off"}`}>
            <label className="check">
              <input
                type="checkbox"
                checked={!!item}
                disabled={readOnly}
                onChange={(e) => set(r.code, e.target.checked ? {} : null)}
              />
              <span>
                <b>
                  <span className="muted">{r.code}</span> {r.title}
                </b>
                {r.description && <small>{r.description}</small>}
              </span>
            </label>
            {item && (
              <>
                <label className="field">
                  <span>Интерфейсы объектов воздействия</span>
                  <input
                    className="input"
                    maxLength={4000}
                    placeholder="Например: веб-интерфейс портала (HTTPS), удалённый доступ по RDP"
                    value={item.interfaces ?? ""}
                    disabled={readOnly}
                    onChange={(e) => set(r.code, { interfaces: e.target.value })}
                  />
                </label>
                <ChipPick
                  label="Объекты воздействия"
                  options={objects.map((o) => ({ value: o.key, label: o.name || o.key }))}
                  value={item.objects}
                  disabled={readOnly}
                  onChange={(v) => set(r.code, { objects: v })}
                />
                <ChipPick
                  label="Нарушители"
                  options={actual.map((c) => ({ value: c, label: c, title: refs.title(c) }))}
                  value={item.intruders}
                  disabled={readOnly}
                  onChange={(v) => set(r.code, { intruders: v })}
                />
              </>
            )}
          </div>
        );
      })}
      <StepActions nav={nav} readOnly={readOnly} dirty={s.dirty} busy={s.busy} error={s.error} onSave={s.save} />
    </>
  );
}

// 5. Сценарии.
function ScenariosStep({ model, refs, readOnly, onSaved, nav }: StepProps & Nav) {
  const s = useStepSave(model, "scenarios", model.steps.scenarios, onSaved);
  const byTactic = new Map(s.data.items.map((i) => [i.tactic, i]));
  const noTechniques = refs.ofKind("technique").length === 0;
  const set = (tactic: string, p: Partial<ScenarioItem> | null) =>
    s.change((d) => {
      if (p === null) return { ...d, items: d.items.filter((i) => i.tactic !== tactic) };
      const cur = d.items.find((i) => i.tactic === tactic);
      const next = { tactic, techniques: [], ...cur, ...p } as ScenarioItem;
      return { ...d, items: cur ? d.items.map((i) => (i.tactic === tactic ? next : i)) : [...d.items, next] };
    });
  return (
    <>
      {noTechniques && (
        <div className="alert alert-info">
          <span className="alert-text">
            Техники приложения 11 в справочник не загружены — сценарий описывается тактиками и примечанием. Техники
            можно добавить в <Link to="/refs/threats?tab=tactics">справочнике</Link>.
          </span>
        </div>
      )}
      {refs.ofKind("tactic").map((t) => {
        const item = byTactic.get(t.code);
        const techniques = refs.children(t.code);
        return (
          <div key={t.code} className="tm-check-row">
            <label className="check">
              <input
                type="checkbox"
                checked={!!item}
                disabled={readOnly}
                onChange={(e) => set(t.code, e.target.checked ? {} : null)}
              />
              <span>
                <b>
                  <span className="muted">{t.code}</span> {t.title}
                </b>
              </span>
            </label>
            {item && techniques.length > 0 && (
              <ChipPick
                label="Техники"
                options={techniques.map((x) => ({ value: x.code, label: x.code, title: x.title }))}
                value={item.techniques}
                disabled={readOnly}
                onChange={(v) => set(t.code, { techniques: v })}
              />
            )}
            {item && (
              <input
                className="input"
                aria-label={`Примечание ${t.code}`}
                placeholder="Как тактика реализуется в системе (необязательно)"
                maxLength={4000}
                value={item.note ?? ""}
                disabled={readOnly}
                onChange={(e) => set(t.code, { note: e.target.value })}
              />
            )}
          </div>
        );
      })}
      <StepActions nav={nav} readOnly={readOnly} dirty={s.dirty} busy={s.busy} error={s.error} onSave={s.save} />
    </>
  );
}

// 6. Угрозы БДУ.
function DecisionPill({ t }: { t: Pick<ModelThreat, "relevant"> }) {
  if (t.relevant === true) return <span className="pill pill-danger">Актуальна</span>;
  if (t.relevant === false) return <span className="pill pill-muted">Не актуальна</span>;
  return <span className="pill pill-warn">Не решено</span>;
}

function ThreatsStep({ model, refs, readOnly, onSaved, nav }: StepProps & Nav) {
  const [opened, setOpened] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const openedThreat = model.threats.find((t) => t.code === opened) ?? null;
  return (
    <>
      <div className="actions tm-threats-head">
        <span className="muted">
          Рассмотрено {model.considered}, актуальных {model.relevant}
        </span>
        {!readOnly && (
          <button type="button" className="btn btn-sm" onClick={() => setAdding(true)}>
            <Plus size={14} /> Добавить из БДУ
          </button>
        )}
      </div>
      {model.threats.length === 0 ? (
        <p className="muted">Угрозы ещё не рассмотрены. Добавьте их из БДУ.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>УБИ</th>
                <th>Угроза</th>
                <th>Нарушает</th>
                <th>Решение</th>
                <th>Обоснование</th>
              </tr>
            </thead>
            <tbody>
              {model.threats.map((t) => (
                <tr
                  key={t.code}
                  className={`clickable${opened === t.code ? " selected" : ""}`}
                  onClick={() => setOpened(t.code)}
                >
                  <td className="nowrap">
                    <button type="button" className="link-btn" onClick={() => setOpened(t.code)}>
                      <span className="tag">{t.code}</span>
                    </button>
                  </td>
                  <td>
                    {t.title ?? <span className="muted">нет в БДУ</span>}
                    {t.withdrawn && <div className="cell-sub">исключена из БДУ</div>}
                  </td>
                  <td className="nowrap">{ciaText(t)}</td>
                  <td>
                    <DecisionPill t={t} />
                  </td>
                  <td className="cell-sub clamp-2">{t.justification ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="actions">{nav}</div>
      {adding && (
        <AddThreats
          model={model}
          onClose={() => setAdding(false)}
          onAdded={(m) => {
            onSaved(m);
            setAdding(false);
          }}
        />
      )}
      {openedThreat && (
        <ThreatDrawer
          key={openedThreat.code}
          t={openedThreat}
          model={model}
          refs={refs}
          readOnly={readOnly}
          onClose={() => setOpened(null)}
          onSaved={onSaved}
        />
      )}
    </>
  );
}

function AddThreats({
  model,
  onClose,
  onAdded,
}: {
  model: ModelDetail;
  onClose: () => void;
  onAdded: (m: ModelDetail) => void;
}) {
  const [q, setQ] = useState("");
  const [match, setMatch] = useState(true);
  const [rows, setRows] = useState<Candidate[] | null>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => {
      const params = new URLSearchParams({ limit: "200" });
      if (q.trim()) params.set("q", q.trim());
      if (match) params.set("match", "true");
      apiGet<Candidate[]>(`/threat-models/${model.id}/candidates?${params}`)
        .then(setRows)
        .catch((e: Error) => setError(e.message));
    }, 200);
    return () => clearTimeout(t);
  }, [q, match, model.id]);

  async function add(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onAdded(await apiSend<ModelDetail>("POST", `/threat-models/${model.id}/threats`, { codes: picked }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось добавить");
      setBusy(false);
    }
  }

  const free = rows?.filter((r) => !r.in_model) ?? [];
  return (
    <Drawer
      title="Угрозы из БДУ"
      subtitle={model.bdu_version ? `Выгрузка от ${model.bdu_version}` : undefined}
      onClose={onClose}
      footer={
        <button type="submit" form="add-threats" className="btn btn-primary" disabled={busy || picked.length === 0}>
          <Plus size={15} /> Добавить {picked.length || ""}
        </button>
      }
    >
      <form id="add-threats" className="drawer-section form-stack" onSubmit={add}>
        {error && <ErrorAlert message={error} />}
        <label className="search-field">
          <Search size={14} aria-hidden="true" />
          <input
            className="input toolbar-search"
            type="search"
            aria-label="Поиск угрозы"
            placeholder="УБИ.006 или часть наименования"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </label>
        <div className="chips">
          <button type="button" className="chip" aria-pressed={match} onClick={() => setMatch(!match)}>
            Только по категории актуальных нарушителей
          </button>
          {free.length > 0 && (
            <button
              type="button"
              className="chip"
              onClick={() => setPicked(picked.length === free.length ? [] : free.map((r) => r.code))}
            >
              {picked.length === free.length ? "Снять все" : `Выбрать все (${free.length})`}
            </button>
          )}
        </div>
        <small className="muted">
          Отбор по категории (внешний/внутренний) из поля «Источник угрозы» БДУ — подсказка, а не правило Методики:
          решение об актуальности принимается по каждой угрозе.
        </small>
        {!rows && <Loading />}
        {rows && rows.length === 0 && <p className="muted">Ничего не найдено. Угрозы БДУ загружаются в справочнике.</p>}
        {rows?.map((r) => (
          <label key={r.code} className={`check${r.in_model ? " tm-block-off" : ""}`}>
            <input
              type="checkbox"
              checked={r.in_model || picked.includes(r.code)}
              disabled={r.in_model}
              onChange={() => setPicked(toggle(picked, r.code))}
            />
            <span>
              <b>
                <span className="muted">{r.code}</span> {r.title}
              </b>
              <small>
                {r.source ?? "Источник не указан"} · нарушает: {ciaText(r)}
                {r.in_model && " · уже в модели"}
              </small>
            </span>
          </label>
        ))}
      </form>
    </Drawer>
  );
}

function ThreatDrawer({
  t,
  model,
  refs,
  readOnly,
  onClose,
  onSaved,
}: {
  t: ModelThreat;
  model: ModelDetail;
  refs: RefIndex;
  readOnly: boolean;
  onClose: () => void;
  onSaved: (m: ModelDetail) => void;
}) {
  const [relevant, setRelevant] = useState<boolean | null>(t.relevant);
  const [justification, setJustification] = useState(t.justification ?? "");
  const [links, setLinks] = useState<Record<LinkKey, string[]>>({
    intruders: t.intruders,
    objects: t.objects,
    consequences: t.consequences,
    methods: t.methods,
    tactics: t.tactics,
  });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const steps: Steps = model.steps;

  const options: Record<LinkKey, { value: string; label: string; title?: string }[]> = useMemo(
    () => ({
      intruders: steps.intruders.items
        .filter((i) => i.relevant)
        .map((i) => ({ value: i.code, label: `${i.code} · ${i.capability ?? "?"}`, title: refs.title(i.code) })),
      objects: steps.objects.items.map((o) => ({ value: o.key, label: o.name || o.key })),
      consequences: steps.consequences.items.map((c) => ({ value: c.code, label: c.code, title: refs.title(c.code) })),
      methods: steps.methods.items.map((m) => ({ value: m.code, label: m.code, title: refs.title(m.code) })),
      tactics: steps.scenarios.items.flatMap((s) => [
        { value: s.tactic, label: s.tactic, title: refs.title(s.tactic) },
        ...s.techniques.map((x) => ({ value: x, label: x, title: refs.title(x) })),
      ]),
    }),
    [steps, refs],
  );

  function decide(v: boolean | null) {
    setRelevant(v);
    if (v === true && Object.values(links).every((l) => l.length === 0)) {
      setLinks(suggestLinks(t, steps, (c) => refs.byCode.get(c)?.attrs.category));
    }
  }

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const body = {
        ...(relevant === null ? { clear_decision: true } : { relevant }),
        justification,
        ...(relevant ? links : {}),
      };
      onSaved(await apiSend<ModelDetail>("PATCH", `/threat-models/${model.id}/threats/${encodeURIComponent(t.code)}`, body));
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось сохранить");
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    try {
      onSaved(await apiSend<ModelDetail>("DELETE", `/threat-models/${model.id}/threats/${encodeURIComponent(t.code)}`));
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось убрать");
      setBusy(false);
    }
  }

  return (
    <Drawer
      title={`${t.code}`}
      subtitle={t.title ?? "Угрозы нет в загруженной БДУ"}
      onClose={onClose}
      footer={
        readOnly ? undefined : (
          <>
            <button type="button" className="btn btn-ghost" disabled={busy} onClick={remove}>
              <Trash2 size={15} /> Убрать из модели
            </button>
            <button type="submit" form="threat-form" className="btn btn-primary" disabled={busy}>
              <Save size={15} /> Сохранить
            </button>
          </>
        )
      }
    >
      <div className="drawer-section">
        <dl className="props">
          <dt>Источник (БДУ)</dt>
          <dd>{t.source ?? "—"}</dd>
          <dt>Объект воздействия (БДУ)</dt>
          <dd>{t.target ?? "—"}</dd>
          <dt>Нарушает</dt>
          <dd>{ciaText(t)}</dd>
        </dl>
        {t.description && <p className="cell-sub">{t.description}</p>}
      </div>
      <form id="threat-form" className="drawer-section drawer-form form-stack" onSubmit={save}>
        {error && <ErrorAlert message={error} />}
        <div className="field">
          <span>Решение</span>
          <div className="seg" role="radiogroup" aria-label="Решение об актуальности">
            {(
              [
                [true, "Актуальна"],
                [false, "Не актуальна"],
                [null, "Не решено"],
              ] as const
            ).map(([v, label]) => (
              <button
                key={label}
                type="button"
                role="radio"
                className="seg-btn"
                aria-checked={relevant === v}
                disabled={readOnly}
                onClick={() => decide(v)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <label className="field">
          <span>Обоснование</span>
          <textarea
            className="textarea"
            rows={3}
            maxLength={4000}
            value={justification}
            disabled={readOnly}
            placeholder={
              relevant === false
                ? "Почему угроза не актуальна: нет нарушителя, объекта или интерфейса"
                : "Через что и кем реализуется угроза в этой системе"
            }
            onChange={(e) => setJustification(e.target.value)}
          />
        </label>
        {relevant === true &&
          (Object.keys(LINK_TITLES) as LinkKey[]).map((k) => (
            <ChipPick
              key={k}
              label={LINK_TITLES[k]}
              options={options[k]}
              value={links[k]}
              disabled={readOnly}
              onChange={(v) => setLinks((prev) => ({ ...prev, [k]: v }))}
            />
          ))}
      </form>
    </Drawer>
  );
}

// 7. Итог.
function ResultStep({
  model,
  refs,
  nav,
  onApprove,
  approveBlocked,
  onNavigate,
}: StepProps &
  Nav & { onApprove?: () => void; approveBlocked: string | null; onNavigate: (v: View) => void }) {
  const relevant = model.threats.filter((t) => t.relevant);
  const notRelevant = model.threats.filter((t) => t.relevant === false);
  const objName = new Map(model.steps.objects.items.map((o) => [o.key, o.name || o.key]));
  const problems = model.progress.steps.filter((s) => !s.done || s.problems.length);
  return (
    <>
      {problems.length > 0 ? (
        <div className="alert alert-warn">
          <span className="alert-text">
            Модель не готова к утверждению:
            <ul className="tm-problems">
              {problems.map((s) => (
                <li key={s.key}>
                  <button type="button" className="link-btn" onClick={() => onNavigate(s.key)}>
                    {s.title}
                  </button>
                  : {s.problems[0] ?? "шаг не заполнен"}
                  {s.problems.length > 1 && ` (и ещё ${s.problems.length - 1})`}
                </li>
              ))}
            </ul>
          </span>
        </div>
      ) : (
        model.status === "draft" && (
          <div className="alert alert-ok">
            <span className="alert-text">Все шаги заполнены — модель можно утверждать.</span>
          </div>
        )
      )}
      <h3>Перечень актуальных угроз</h3>
      {relevant.length === 0 ? (
        <p className="muted">Актуальных угроз нет.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>УБИ</th>
                <th>Угроза и обоснование</th>
                <th>Нарушители</th>
                <th>Объекты воздействия</th>
                <th>Последствия</th>
              </tr>
            </thead>
            <tbody>
              {relevant.map((t) => (
                <tr key={t.code}>
                  <td className="nowrap">
                    <span className="tag">{t.code}</span>
                  </td>
                  <td>
                    <div className="cell-title">{t.title ?? "—"}</div>
                    <div className="cell-sub">{t.justification}</div>
                  </td>
                  <td>
                    {t.intruders.map((c) => (
                      <div key={c} title={refs.title(c)} className="nowrap">
                        {c}
                      </div>
                    ))}
                  </td>
                  <td>{t.objects.map((k) => objName.get(k) ?? k).join("; ")}</td>
                  <td>
                    <span title={t.consequences.map((c) => `${c} ${refs.title(c)}`).join("\n")}>
                      {t.consequences.join(", ")}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {notRelevant.length > 0 && (
        <details className="tm-details">
          <summary>Неактуальные угрозы: {notRelevant.length}</summary>
          <ul className="tm-problems">
            {notRelevant.map((t) => (
              <li key={t.code}>
                <b>{t.code}</b> {t.title} — <span className="muted">{t.justification}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
      <div className="actions">
        {nav}
        {onApprove && (
          <>
            {approveBlocked && <span className="cell-sub">{approveBlocked}</span>}
            <button
              type="button"
              className="btn btn-primary"
              disabled={approveBlocked !== null}
              title={approveBlocked ?? undefined}
              onClick={onApprove}
            >
              <CheckCheck size={15} /> Утвердить модель
            </button>
          </>
        )}
      </div>
    </>
  );
}

function ApproveDialog({
  model,
  onClose,
  onDone,
}: {
  model: ModelDetail;
  onClose: () => void;
  onDone: (m: ModelDetail) => void;
}) {
  const [comment, setComment] = useState("");
  const [ack, setAck] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const needAck = model.unverified_refs.length > 0;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onDone(
        await apiSend<ModelDetail>("POST", `/threat-models/${model.id}/approve`, {
          comment: comment.trim() || null,
          acknowledge_unverified: ack,
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось утвердить");
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Утвердить модель угроз"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="approve-tm" className="btn btn-primary" disabled={busy || (needAck && !ack)}>
            Утвердить
          </button>
        </>
      }
    >
      <form id="approve-tm" className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <p>
          Версия {model.version}: актуальных угроз <b>{model.relevant}</b> из {model.considered} рассмотренных.
          Утверждение фиксируется в журнале; записи справочника и угрозы БДУ сохраняются в снимке версии, прежняя
          утверждённая версия станет заменённой.
        </p>
        {needAck && (
          <label className="check">
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
            <span>
              <b>Утверждаю по несверенному справочнику</b>
              <small>
                Модель ссылается на {model.unverified_refs.length} записей Методики, не сверенных методистом с
                официальным текстом. В документах модель будет помечена как основанная на несверенных данных.
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
