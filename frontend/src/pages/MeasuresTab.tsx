import {
  BadgeCheck,
  CheckCheck,
  History,
  ListChecks,
  Paperclip,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Drawer } from "../components/Drawer";
import { ImplBar } from "../components/ImplBar";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { VerifyBadge } from "../components/VerifyBadge";
import { apiGet, apiSend } from "../lib/api";
import { useAuth } from "../lib/auth";
import { awaitsConfirmation } from "../lib/evidence";
import { formatDateTime, formatNumber } from "../lib/format";
import {
  ADAPTATION_STATUS_LABELS,
  METHOD_LABELS,
  STATUS_LABELS,
  STATUS_ORDER,
  STATUS_PILL,
  adaptationNote,
  differsFromScanner,
  formatPercent,
  type AdaptationKind,
  type AdaptationVersion,
  type MeasureSet,
  type MeasureStatus,
  type ObjectMeasure,
  type Plan,
  type StatsBucket,
} from "../lib/measures";
import type { ObjectFull } from "../lib/objects";
import { useProject } from "../lib/project";
import { ConfirmSection, ManualEvidenceSection } from "./ManualEvidence";
import { MeasureEvidence, ScannerCard } from "./ScannerResults";

type Filter =
  | "all"
  | "unassessed"
  | "manual"
  | "unconfirmed"
  | "differs"
  | "adapted"
  | "review";
const FILTERS: [Filter, string][] = [
  ["all", "Все"],
  ["unassessed", "Не оценены"],
  ["manual", "Требуют ручной оценки"],
  ["unconfirmed", "Ждут подтверждения"],
  ["differs", "Расходятся со «Сканером»"],
  ["adapted", "Адаптация"],
  ["review", "Требуют сверки"],
];

function message(e: unknown, fallback: string): string {
  return e instanceof Error ? e.message : fallback;
}

export function MeasuresTab({
  obj,
  editable,
  onChanged,
}: {
  obj: ObjectFull;
  editable: boolean;
  onChanged: () => void;
}) {
  const { can } = useAuth();
  const [set, setSet] = useState<MeasureSet | null>(null);
  const [items, setItems] = useState<ObjectMeasure[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [group, setGroup] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  // ?measure=<id> — открыть карточку меры по ссылке (быстрый поиск Ctrl+K).
  const [params, setParams] = useSearchParams();
  const linked = params.get("measure");
  const [opened, setOpened] = useState<string | null>(linked);
  const [rebuilding, setRebuilding] = useState(false);
  const [adding, setAdding] = useState(false);
  const [approving, setApproving] = useState(false);
  const [history, setHistory] = useState<AdaptationVersion[] | null>(null);

  const load = useCallback(() => {
    setError(null);
    apiGet<MeasureSet>(`/objects/${obj.id}/measure-set`)
      .then((s) => {
        setSet(s);
        if (s.state === "built") {
          apiGet<ObjectMeasure[]>(`/objects/${obj.id}/measures`)
            .then(setItems)
            .catch((e: Error) => setError(e.message));
          apiGet<AdaptationVersion[]>(`/objects/${obj.id}/adaptations`)
            .then(setHistory)
            .catch((e: Error) => setError(e.message));
        } else {
          setItems([]);
          setHistory([]);
        }
      })
      .catch((e: Error) => setError(e.message));
  }, [obj.id]);

  useEffect(load, [load]);

  useEffect(() => {
    if (linked) setOpened(linked);
  }, [linked]);

  const close = () => {
    setOpened(null);
    if (params.has("measure")) {
      const next = new URLSearchParams(params);
      next.delete("measure");
      setParams(next, { replace: true });
    }
  };

  const reload = () => {
    load();
    onChanged();
  };

  const filtered = useMemo(() => {
    const q = query.trim().toLocaleLowerCase("ru-RU");
    return (items ?? []).filter((m) => {
      if (group && m.group_code !== group) return false;
      if (filter === "unassessed" && m.status !== "unassessed") return false;
      // Организационная мера ждёт ручной оценки, пока её не подтвердили.
      if (
        filter === "manual" &&
        (m.method !== "manual" ||
          m.confirmed_at !== null ||
          m.adaptation === "excluded")
      )
        return false;
      if (filter === "unconfirmed" && !awaitsConfirmation(m)) return false;
      if (filter === "differs" && !differsFromScanner(m)) return false;
      if (
        filter === "adapted" &&
        m.adaptation === "none" &&
        m.origin !== "added"
      )
        return false;
      if (filter === "review" && m.verified) return false;
      if (
        q &&
        !m.measure_id.toLocaleLowerCase("ru-RU").includes(q) &&
        !m.title.toLocaleLowerCase("ru-RU").includes(q)
      )
        return false;
      return true;
    });
  }, [items, group, filter, query]);

  const byGroup = useMemo(() => {
    const out = new Map<string, ObjectMeasure[]>();
    for (const m of filtered)
      out.set(m.group_code, [...(out.get(m.group_code) ?? []), m]);
    return out;
  }, [filtered]);

  if (error && !set) return <ErrorAlert message={error} onRetry={load} />;
  if (!set || !items) return <Loading />;

  const canAdapt = editable && can("adaptation.edit");
  const canAssess = editable && can("assessment.edit");
  const canApprove = editable && can("approve");
  const canImport = editable && can("scanner.import");
  const canUpload = editable && can("evidence.upload");

  if (set.state === "no_regime" || set.state === "no_profile") {
    return (
      <section className="card">
        <EmptyState
          icon={<ListChecks size={21} />}
          title={
            set.state === "no_regime"
              ? "Режим не выбран"
              : "Профиль мер не загружен"
          }
          text={
            set.state === "no_regime"
              ? "Набор мер формируется для ГИС, ИСПДн и КИИ. Укажите вид объекта и нормативный режим в описании."
              : "В справочнике нет мер для режима объекта. Обратитесь к администратору."
          }
        />
      </section>
    );
  }

  if (set.state === "no_class") {
    return (
      <section className="card">
        <EmptyState
          icon={<ListChecks size={21} />}
          title="Класс не утверждён"
          text="Базовый набор мер берётся по утверждённому классу (уровню защищённости, категории). Сначала утвердите классификацию."
          action={
            <Link className="btn" to={`/objects/${obj.id}?tab=classification`}>
              К классификации
            </Link>
          }
        />
      </section>
    );
  }

  const a = set.adaptation;
  const opener = items.find((m) => m.id === opened) ?? null;

  return (
    <>
      {error && <ErrorAlert message={error} />}

      {set.state === "not_built" ? (
        <section className="card">
          <EmptyState
            icon={<ListChecks size={21} />}
            title="Набор мер не сформирован"
            text={`${set.classification?.result_label ?? ""} утверждён. Базовый набор возьмётся из профиля ${set.profile_short ?? ""} по столбцу класса; затем его можно адаптировать.`}
            action={
              canAdapt ? (
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => setRebuilding(true)}
                >
                  <ListChecks size={15} /> Сформировать базовый набор
                </button>
              ) : undefined
            }
          />
        </section>
      ) : (
        <>
          {(set.class_changed || set.rebuild_needed) && (
            <div className="alert alert-warn">
              <span className="alert-text">
                {set.class_changed
                  ? `Класс объекта утверждён заново (${set.classification?.result_label}). Набор собран по прежнему классу ${a?.level_label} — пересоберите его.`
                  : "Набор отличается от базового по текущему классу: справочник мер изменился. Пересоберите набор."}
              </span>
              {canAdapt && (
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => setRebuilding(true)}
                >
                  <RefreshCw size={14} /> Пересобрать
                </button>
              )}
            </div>
          )}
          {set.unverified > 0 && (
            <div className="alert alert-info">
              <span className="alert-text">
                Состав базового набора взят из профиля «Сканера» (
                {set.profile_short}) и не сверен методистом:{" "}
                {formatNumber(set.unverified)} из{" "}
                {formatNumber(set.counts.total)} мер требуют сверки.
              </span>
            </div>
          )}

          <div className="measure-kpis">
            <StatCard
              title="Всего"
              bucket={set.stats?.total}
              accent
              extra={
                set.confirmed + set.to_confirm > 0
                  ? `подтверждено ${formatNumber(set.confirmed)}${set.to_confirm ? ` · ждут подтверждения ${formatNumber(set.to_confirm)}` : ""}`
                  : undefined
              }
            />
            <StatCard
              title="Автоматически"
              hint="меры с проверками «Сканера»"
              bucket={set.stats?.auto}
            />
            <StatCard
              title="Вручную"
              hint="организационные меры"
              bucket={set.stats?.manual}
            />
            {a && (
              <AdaptationCard
                set={set}
                a={a}
                canAdapt={canAdapt}
                canApprove={canApprove}
                onRebuild={() => setRebuilding(true)}
                onApprove={() => setApproving(true)}
              />
            )}
          </div>

          <ScannerCard
            objectId={obj.id}
            snapshot={set.snapshot}
            linked={obj.scanner_engagement_id !== null}
            canImport={canImport}
            onImported={reload}
          />

          <div className="toolbar measure-toolbar">
            <select
              className="select toolbar-select"
              aria-label="Группа мер"
              value={group}
              onChange={(e) => setGroup(e.target.value)}
            >
              <option value="">Все группы</option>
              {set.groups.map((g) => (
                <option key={g.code} value={g.code}>
                  {g.code} — {g.title}
                </option>
              ))}
            </select>
            <div className="chips" role="group" aria-label="Фильтр">
              {FILTERS.map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  className="chip"
                  aria-pressed={filter === value}
                  onClick={() => setFilter(value)}
                >
                  {label}
                </button>
              ))}
            </div>
            <label className="search-field">
              <Search size={14} aria-hidden="true" />
              <input
                className="input"
                type="search"
                placeholder="Мера или наименование"
                aria-label="Поиск меры"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </label>
            {canAdapt && (
              <button
                type="button"
                className="btn toolbar-end"
                onClick={() => setAdding(true)}
              >
                <Plus size={15} /> Дополнить
              </button>
            )}
          </div>

          {filtered.length === 0 && (
            <section className="card">
              <EmptyState
                icon={<CheckCheck size={21} />}
                title="Ничего не найдено"
                text="Под выбранные фильтры мер нет."
              />
            </section>
          )}

          {set.groups
            .filter((g) => byGroup.has(g.code))
            .map((g) => (
              <section key={g.code} className="card">
                <div className="card-head">
                  <h2>
                    <span className="tag">{g.code}</span> {g.title}
                  </h2>
                  <span className="count">{byGroup.get(g.code)?.length}</span>
                </div>
                <div className="table-wrap">
                  <table className="table measures-table">
                    <thead>
                      <tr>
                        <th>Мера</th>
                        <th>Наименование</th>
                        <th>Оценка</th>
                        <th>Статус</th>
                        <th>Сверка</th>
                      </tr>
                    </thead>
                    <tbody>
                      {byGroup.get(g.code)?.map((m) => (
                        <MeasureRow
                          key={m.id}
                          m={m}
                          selected={opened === m.id}
                          onOpen={() => setOpened(m.id)}
                        />
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            ))}

          {history && history.length > 0 && <HistoryCard history={history} />}
        </>
      )}

      {rebuilding && (
        <RebuildDialog
          objectId={obj.id}
          first={set.state === "not_built"}
          onClose={() => setRebuilding(false)}
          onDone={() => {
            setRebuilding(false);
            reload();
          }}
        />
      )}
      {adding && set.profile_id && (
        <AddDialog
          objectId={obj.id}
          profileId={set.profile_id}
          have={new Set(items.map((m) => m.measure_id))}
          onClose={() => setAdding(false)}
          onDone={(m) => {
            setAdding(false);
            reload();
            setOpened(m.id);
          }}
        />
      )}
      {approving && a && (
        <ApproveDialog
          objectId={obj.id}
          set={set}
          a={a}
          onClose={() => setApproving(false)}
          onDone={() => {
            setApproving(false);
            reload();
          }}
        />
      )}
      {opener && (
        <MeasureDrawer
          key={`${opener.id}-${opener.updated_at}`}
          m={opener}
          all={items}
          projectId={obj.project_id}
          canAdapt={canAdapt}
          canAssess={canAssess}
          canUpload={canUpload}
          onClose={close}
          onChanged={() => reload()}
          onRemoved={() => {
            close();
            reload();
          }}
        />
      )}
    </>
  );
}

// ---------- Сводка ----------

function StatCard({
  title,
  hint,
  bucket,
  accent,
  extra,
}: {
  title: string;
  hint?: string;
  bucket: StatsBucket | undefined;
  accent?: boolean;
  extra?: string;
}) {
  return (
    <div className={`card kpi measure-kpi${accent ? " measure-kpi-main" : ""}`}>
      <span className="kpi-label">
        {title}
        {hint && <span className="muted"> · {hint}</span>}
      </span>
      <span className="kpi-value">{formatPercent(bucket?.percent)}</span>
      <ImplBar bucket={bucket} />
      {bucket && (
        <span className="kpi-delta">
          {formatNumber(bucket.total)} мер в проценте
          {bucket.unassessed > 0 &&
            ` · ${formatNumber(bucket.unassessed)} не оценено`}
          {bucket.excluded > 0 && ` · ${formatNumber(bucket.excluded)} искл.`}
          {bucket.not_applicable > 0 &&
            ` · ${formatNumber(bucket.not_applicable)} не примен.`}
        </span>
      )}
      {extra && (
        <span className="kpi-delta confirmed-mark">
          <BadgeCheck size={13} aria-hidden="true" /> {extra}
        </span>
      )}
    </div>
  );
}

function AdaptationCard({
  set,
  a,
  canAdapt,
  canApprove,
  onRebuild,
  onApprove,
}: {
  set: MeasureSet;
  a: AdaptationVersion;
  canAdapt: boolean;
  canApprove: boolean;
  onRebuild: () => void;
  onApprove: () => void;
}) {
  const { me } = useAuth();
  const own = !!me && a.editor_ids.includes(me.id);
  return (
    <div className="card kpi measure-kpi">
      <span className="kpi-label">
        Адаптация · версия {a.version} · {a.level_label}
      </span>
      <div>
        <span
          className={`pill ${a.status === "approved" ? "pill-ok" : "pill-warn"}`}
        >
          {ADAPTATION_STATUS_LABELS[a.status]}
        </span>
      </div>
      <span className="kpi-delta">
        {a.status === "approved"
          ? `Утвердил ${a.approved_by_name}, ${formatDateTime(a.approved_at)}`
          : `Черновик от ${formatDateTime(a.created_at)}, ${a.created_by_name}${a.edits ? ` · правок: ${a.edits}` : ""}`}
      </span>
      <span className="kpi-delta">
        Исключено {set.counts.excluded} · компенсировано{" "}
        {set.counts.compensated} · дополнено {set.counts.added}
      </span>
      <div className="actions">
        {canApprove && a.status === "draft" && (
          <button
            type="button"
            className="btn btn-sm btn-primary"
            disabled={own || set.approve_blockers.length > 0}
            title={
              own
                ? "Вы меняли эту версию адаптации — утверждает другой"
                : set.approve_blockers.join("; ")
            }
            onClick={onApprove}
          >
            <ShieldCheck size={14} /> Утвердить
          </button>
        )}
        {canAdapt && (
          <button type="button" className="btn btn-sm" onClick={onRebuild}>
            <RefreshCw size={14} /> Пересобрать
          </button>
        )}
      </div>
    </div>
  );
}

function MeasureRow({
  m,
  selected,
  onOpen,
}: {
  m: ObjectMeasure;
  selected: boolean;
  onOpen: () => void;
}) {
  const note = adaptationNote(m);
  const excluded = m.adaptation === "excluded";
  return (
    <tr
      className={`clickable${selected ? " selected" : ""}${excluded ? " row-excluded" : ""}`}
      onClick={onOpen}
    >
      <td className="nowrap">
        <button type="button" className="link-btn" onClick={onOpen}>
          <span className="tag">{m.measure_id}</span>
        </button>
      </td>
      <td>
        <div className="measure-title">{m.title}</div>
        {note && <div className="cell-sub measure-note">{note}</div>}
      </td>
      <td className="nowrap">
        {m.method === "auto" ? (
          <span className="pill pill-info">{METHOD_LABELS[m.method]}</span>
        ) : (
          <span className="pill pill-muted">{METHOD_LABELS[m.method]}</span>
        )}
        {m.manual_evidence > 0 && (
          <div
            className="cell-sub evidence-count"
            title="Ручные доказательства"
          >
            <Paperclip size={12} aria-hidden="true" /> {m.manual_evidence}
          </div>
        )}
      </td>
      <td className="nowrap">
        {excluded ? (
          <span className="pill pill-muted">Исключена</span>
        ) : m.adaptation === "compensated" && m.effective_status ? (
          <span
            className={`pill ${STATUS_PILL[m.effective_status]}`}
            title="По статусу компенсирующих мер"
          >
            {STATUS_LABELS[m.effective_status]} · комп.
          </span>
        ) : (
          <span
            className={`pill ${STATUS_PILL[m.status]}`}
            title={
              m.status_source === "auto"
                ? (m.auto_note ?? undefined)
                : undefined
            }
          >
            {STATUS_LABELS[m.status]}
          </span>
        )}
        {m.confirmed_at && !excluded ? (
          <div className="cell-sub confirmed-mark">
            <BadgeCheck size={12} aria-hidden="true" /> подтверждена
          </div>
        ) : (
          m.status_source === "auto" &&
          !excluded && <div className="cell-sub">по «Сканеру»</div>
        )}
        {differsFromScanner(m) && m.auto_status && (
          <div className="cell-sub status-differs">
            «Сканер»: {STATUS_LABELS[m.auto_status]}
          </div>
        )}
      </td>
      <td>
        <VerifyBadge verified={m.verified} />
      </td>
    </tr>
  );
}

function HistoryCard({ history }: { history: AdaptationVersion[] }) {
  return (
    <section className="card">
      <div className="card-head">
        <h2>
          <History size={16} /> История адаптации
        </h2>
        <span className="count">{history.length}</span>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Версия</th>
              <th>Класс</th>
              <th>Статус</th>
              <th>Создал</th>
              <th>Утвердил</th>
              <th>Состав при утверждении</th>
            </tr>
          </thead>
          <tbody>
            {history.map((v) => (
              <tr key={v.id}>
                <td>{v.version}</td>
                <td className="nowrap">{v.level_label}</td>
                <td>
                  <span
                    className={`pill ${v.status === "approved" ? "pill-ok" : v.status === "draft" ? "pill-warn" : "pill-muted"}`}
                  >
                    {ADAPTATION_STATUS_LABELS[v.status]}
                  </span>
                </td>
                <td>
                  {v.created_by_name}
                  <div className="cell-sub">{formatDateTime(v.created_at)}</div>
                </td>
                <td>
                  {v.approved_by_name ?? <span className="muted">—</span>}
                  {v.approved_at && (
                    <div className="cell-sub">
                      {formatDateTime(v.approved_at)}
                      {v.unverified_acknowledged &&
                        " · по несверенному справочнику"}
                    </div>
                  )}
                </td>
                <td className="cell-sub">
                  {v.counts
                    ? `${v.counts.total} мер · искл. ${v.counts.excluded} · комп. ${v.counts.compensated} · доп. ${v.counts.added}`
                    : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

// ---------- Пересборка ----------

function PlanList({
  title,
  items,
  warn,
}: {
  title: string;
  items: Plan["add"];
  warn?: boolean;
}) {
  if (items.length === 0) return null;
  return (
    <div className="plan-list">
      <h3>
        {title} <span className="count">{items.length}</span>
      </h3>
      <ul>
        {items.map((i) => (
          <li key={i.measure_id}>
            <span className="tag">{i.measure_id}</span> {i.title}
            {warn && i.assessed && (
              <span className="pill pill-warn">есть оценка</span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function RebuildDialog({
  objectId,
  first,
  onClose,
  onDone,
}: {
  objectId: string;
  first: boolean;
  onClose: () => void;
  onDone: () => void;
}) {
  const [plan, setPlan] = useState<Plan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiSend<Plan>("POST", `/objects/${objectId}/measures/rebuild`, {
      dry_run: true,
    })
      .then(setPlan)
      .catch((e: Error) => setError(e.message));
  }, [objectId]);

  async function apply() {
    setBusy(true);
    setError(null);
    try {
      await apiSend<Plan>("POST", `/objects/${objectId}/measures/rebuild`, {
        dry_run: false,
      });
      onDone();
    } catch (e) {
      setError(message(e, "Не удалось пересобрать набор"));
      setBusy(false);
    }
  }

  return (
    <Modal
      title={first ? "Сформировать базовый набор" : "Пересобрать набор"}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy || !plan || !plan.changes}
            onClick={apply}
          >
            {first ? "Сформировать" : "Применить"}
          </button>
        </>
      }
    >
      <div className="form-stack">
        {error && <ErrorAlert message={error} />}
        {!plan && !error && <Loading />}
        {plan && (
          <>
            <p>
              По классу <b>{plan.classification.result_label}</b>: меры профиля,
              у которых класс отмечен в базовом наборе.
              {!first &&
                " Адаптация остальных мер сохранится; изменение откроет новую версию адаптации."}
            </p>
            {plan.empty && !plan.changes && (
              <p className="muted">
                Набор уже совпадает с базовым — менять нечего.
              </p>
            )}
            {plan.empty && plan.changes && !first && (
              <p className="muted">
                Состав не меняется; версия адаптации привяжется к новой
                классификации.
              </p>
            )}
            <PlanList title="Войдут в набор" items={plan.add} />
            <PlanList title="Уйдут из набора" items={plan.remove} warn />
            <PlanList
              title="Дополненные станут базовыми"
              items={plan.promote}
            />
            <PlanList
              title="Компенсация снимется: компенсирующих не останется"
              items={plan.reset}
            />
            {plan.foreign.length > 0 && (
              <p className="muted">
                Меры прежнего режима уйдут из набора: {plan.foreign.length}.
              </p>
            )}
            {plan.remove.some((i) => i.assessed) && (
              <div className="alert alert-warn">
                <span className="alert-text">
                  У части уходящих мер есть оценка — она сохранится только в
                  журнале аудита.
                </span>
              </div>
            )}
          </>
        )}
      </div>
    </Modal>
  );
}

// ---------- Дополнение ----------

interface RefMeasure {
  id: string;
  group_code: string;
  title: string;
  levels: string[];
  kind: string;
}

function AddDialog({
  objectId,
  profileId,
  have,
  onClose,
  onDone,
}: {
  objectId: string;
  profileId: string;
  have: Set<string>;
  onClose: () => void;
  onDone: (m: ObjectMeasure) => void;
}) {
  const [refs, setRefs] = useState<RefMeasure[] | null>(null);
  const [picked, setPicked] = useState("");
  const [q, setQ] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiGet<RefMeasure[]>(
      `/refs/measures?profile=${encodeURIComponent(profileId)}&limit=500`,
    )
      .then(setRefs)
      .catch((e: Error) => setError(e.message));
  }, [profileId]);

  const options = useMemo(() => {
    const needle = q.trim().toLocaleLowerCase("ru-RU");
    return (refs ?? [])
      .filter((r) => !have.has(r.id))
      .filter(
        (r) =>
          !needle ||
          r.id.toLocaleLowerCase("ru-RU").includes(needle) ||
          r.title.toLocaleLowerCase("ru-RU").includes(needle),
      );
  }, [refs, have, q]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onDone(
        await apiSend<ObjectMeasure>("POST", `/objects/${objectId}/measures`, {
          measure_id: picked,
          reason: reason.trim(),
        }),
      );
    } catch (err) {
      setError(message(err, "Не удалось дополнить набор"));
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Дополнить набор мерой"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="submit"
            form="add-measure"
            className="btn btn-primary"
            disabled={busy || !picked || !reason.trim()}
          >
            Дополнить
          </button>
        </>
      }
    >
      <form id="add-measure" className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <label className="field">
          <span>Поиск</span>
          <input
            className="input"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="ИАФ.2, мобильные…"
          />
        </label>
        <div
          className="pick-list"
          role="listbox"
          aria-label="Меры профиля вне набора"
        >
          {!refs && !error && <Loading />}
          {refs && options.length === 0 && (
            <p className="muted">Все меры профиля уже в наборе.</p>
          )}
          {options.map((r) => (
            <label
              key={r.id}
              className={`pick-item${picked === r.id ? " picked" : ""}`}
            >
              <input
                type="radio"
                name="measure"
                value={r.id}
                checked={picked === r.id}
                onChange={() => setPicked(r.id)}
              />
              <span className="tag">{r.id}</span>
              <span>
                {r.title}
                <small className="muted">
                  {" "}
                  ·{" "}
                  {r.levels.length
                    ? `базовая для ${r.levels.join(", ")}`
                    : "вне базового набора"}
                </small>
              </span>
            </label>
          ))}
        </div>
        <label className="field">
          <span>Обоснование дополнения</span>
          <textarea
            className="textarea"
            rows={3}
            maxLength={4000}
            required
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Например: актуальная угроза УБИ.xxx из модели угроз"
          />
        </label>
      </form>
    </Modal>
  );
}

// ---------- Утверждение ----------

function ApproveDialog({
  objectId,
  set,
  a,
  onClose,
  onDone,
}: {
  objectId: string;
  set: MeasureSet;
  a: AdaptationVersion;
  onClose: () => void;
  onDone: () => void;
}) {
  const [comment, setComment] = useState("");
  const [ack, setAck] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const needAck = set.unverified > 0;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiSend("POST", `/objects/${objectId}/adaptation/approve`, {
        comment: comment.trim() || null,
        acknowledge_unverified: ack,
        version: a.version,
      });
      onDone();
    } catch (err) {
      setError(message(err, "Не удалось утвердить"));
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Утвердить адаптацию"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="submit"
            form="approve-adaptation"
            className="btn btn-primary"
            disabled={busy || (needAck && !ack)}
          >
            Утвердить
          </button>
        </>
      }
    >
      <form id="approve-adaptation" className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <p>
          Набор по классу <b>{a.level_label}</b>: {set.counts.total} мер, из них
          исключено {set.counts.excluded}, компенсировано{" "}
          {set.counts.compensated}, дополнено {set.counts.added}. Снимок
          адаптации сохранится в версии {a.version}; утверждение фиксируется в
          журнале аудита.
        </p>
        {needAck && (
          <label className="check">
            <input
              type="checkbox"
              checked={ack}
              onChange={(e) => setAck(e.target.checked)}
            />
            <span>
              <b>Утверждаю по несверенному справочнику</b>
              <small>
                {set.unverified} мер набора не сверены методистом: состав
                базового набора и сопоставление с проверками «Сканера» могут
                отличаться от официального текста.
              </small>
            </span>
          </label>
        )}
        <label className="field">
          <span>Комментарий</span>
          <textarea
            className="textarea"
            rows={2}
            maxLength={2000}
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
        </label>
      </form>
    </Modal>
  );
}

// ---------- Карточка меры ----------

function MeasureDrawer({
  m,
  all,
  projectId,
  canAdapt,
  canAssess,
  canUpload,
  onClose,
  onChanged,
  onRemoved,
}: {
  m: ObjectMeasure;
  all: ObjectMeasure[];
  projectId: string;
  canAdapt: boolean;
  canAssess: boolean;
  canUpload: boolean;
  onClose: () => void;
  onChanged: () => void;
  onRemoved: () => void;
}) {
  const { projects } = useProject();
  const members = projects.find((p) => p.id === projectId)?.members ?? [];
  const [kind, setKind] = useState<AdaptationKind>(m.adaptation);
  const [reason, setReason] = useState(m.adaptation_reason ?? "");
  const [comp, setComp] = useState<string[]>(m.compensating_ids);
  const [status, setStatus] = useState<MeasureStatus>(m.status);
  const [owner, setOwner] = useState(m.owner_id ?? "");
  const [comment, setComment] = useState(m.comment ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const candidates = all.filter(
    (x) =>
      x.measure_id !== m.measure_id &&
      x.adaptation === "none" &&
      !comp.includes(x.measure_id),
  );
  const adaptDirty =
    kind !== m.adaptation ||
    (kind !== "none" || m.origin === "added"
      ? reason.trim() !== (m.adaptation_reason ?? "")
      : false) ||
    (kind === "compensated" && comp.join() !== m.compensating_ids.join());
  const assessDirty =
    status !== m.status ||
    owner !== (m.owner_id ?? "") ||
    comment.trim() !== (m.comment ?? "");

  async function save(body: Record<string, unknown>) {
    setBusy(true);
    setError(null);
    try {
      await apiSend("PATCH", `/object-measures/${m.id}`, body);
      onChanged();
    } catch (e) {
      setError(message(e, "Не удалось сохранить"));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    setError(null);
    try {
      await apiSend("DELETE", `/object-measures/${m.id}`);
      onRemoved();
    } catch (e) {
      setError(message(e, "Не удалось убрать меру"));
      setBusy(false);
    }
  }

  return (
    <Drawer
      title={
        <>
          <span className="tag">{m.measure_id}</span> {m.title}
        </>
      }
      subtitle={`${m.origin === "added" ? "Дополнение" : "Базовый набор"} · ${METHOD_LABELS[m.method]}`}
      onClose={onClose}
    >
      {error && (
        <div className="drawer-section">
          <ErrorAlert message={error} />
        </div>
      )}
      <div className="drawer-section">
        <dl className="props">
          <dt>Статус</dt>
          <dd>
            <span className={`pill ${STATUS_PILL[m.status]}`}>
              {STATUS_LABELS[m.status]}
            </span>
            {m.adaptation === "compensated" && m.effective_status && (
              <span className="muted">
                {" "}
                · в проценте: {STATUS_LABELS[m.effective_status]} (по
                компенсирующим)
              </span>
            )}
            {m.adaptation === "excluded" && (
              <span className="muted"> · вне процента</span>
            )}
          </dd>
          <dt>Базовый набор</dt>
          <dd>
            {m.levels.length ? (
              m.levels.join(", ")
            ) : (
              <span className="muted">вне базового набора</span>
            )}
          </dd>
          <dt>Проверки «Сканера»</dt>
          <dd>
            {m.checks.length ? (
              m.checks.join(", ")
            ) : (
              <span className="muted">нет — проверяется вручную</span>
            )}
          </dd>
          <dt>Сверка</dt>
          <dd>
            <VerifyBadge verified={m.verified} />
          </dd>
          {m.compensates.length > 0 && (
            <>
              <dt>Компенсирует</dt>
              <dd>{m.compensates.join(", ")}</dd>
            </>
          )}
          {m.status_by_name && (
            <>
              <dt>Статус ставил</dt>
              <dd>
                {m.status_by_name}, {formatDateTime(m.status_at)}
              </dd>
            </>
          )}
        </dl>
        {!m.in_reference && (
          <div className="alert alert-warn">
            <span className="alert-text">
              Мера убрана из справочника — пересоберите набор.
            </span>
          </div>
        )}
      </div>

      <div className="drawer-section">
        <h3>Адаптация</h3>
        {canAdapt ? (
          <form
            className="form-stack drawer-form"
            onSubmit={(e) => {
              e.preventDefault();
              void save({
                adaptation: kind,
                adaptation_reason: reason.trim() || null,
                ...(kind === "compensated" ? { compensating_ids: comp } : {}),
              });
            }}
          >
            <div className="seg" role="radiogroup" aria-label="Адаптация меры">
              {(
                [
                  [
                    "none",
                    m.origin === "added" ? "Дополнение" : "Без изменений",
                  ],
                  ["excluded", "Исключить"],
                  ["compensated", "Компенсировать"],
                ] as [AdaptationKind, string][]
              )
                .filter(([k]) => !(k === "excluded" && m.origin === "added"))
                .map(([k, label]) => (
                  <button
                    key={k}
                    type="button"
                    role="radio"
                    aria-checked={kind === k}
                    className="seg-btn"
                    onClick={() => setKind(k)}
                  >
                    {label}
                  </button>
                ))}
            </div>
            {m.compensates.length > 0 && kind !== "none" && (
              <p className="cell-sub">
                Мера компенсирует {m.compensates.join(", ")} — сначала уберите
                её оттуда.
              </p>
            )}
            {kind === "compensated" && (
              <div className="field">
                <span>Компенсирующие меры</span>
                <div className="chips">
                  {comp.map((c) => (
                    <button
                      key={c}
                      type="button"
                      className="chip"
                      aria-pressed="true"
                      title="Убрать"
                      onClick={() => setComp(comp.filter((x) => x !== c))}
                    >
                      {c} ×
                    </button>
                  ))}
                </div>
                <select
                  className="select"
                  aria-label="Добавить компенсирующую меру"
                  value=""
                  onChange={(e) =>
                    e.target.value && setComp([...comp, e.target.value])
                  }
                >
                  <option value="">Добавить меру набора…</option>
                  {candidates.map((x) => (
                    <option key={x.measure_id} value={x.measure_id}>
                      {x.measure_id} — {x.title}
                    </option>
                  ))}
                </select>
              </div>
            )}
            {(kind !== "none" || m.origin === "added") && (
              <label className="field">
                <span>
                  {kind === "excluded"
                    ? "Обоснование исключения"
                    : kind === "compensated"
                      ? "Обоснование компенсации"
                      : "Обоснование дополнения"}
                </span>
                <textarea
                  className="textarea"
                  rows={3}
                  maxLength={4000}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder={
                    kind === "excluded"
                      ? "Например: нет беспроводного доступа — угроза не актуальна"
                      : "Почему мера закрыта иначе"
                  }
                />
              </label>
            )}
            <div className="actions">
              <button
                type="submit"
                className="btn btn-primary btn-sm"
                disabled={busy || !adaptDirty}
              >
                Сохранить адаптацию
              </button>
              {m.origin === "added" && (
                <button
                  type="button"
                  className="btn btn-sm btn-danger"
                  disabled={busy}
                  onClick={remove}
                >
                  <Trash2 size={14} /> Убрать из набора
                </button>
              )}
            </div>
            {m.adapted_by_name && (
              <p className="cell-sub">
                Изменил {m.adapted_by_name}, {formatDateTime(m.adapted_at)}
              </p>
            )}
          </form>
        ) : (
          <p>
            {adaptationNote(m) ?? <span className="muted">Без изменений</span>}
          </p>
        )}
      </div>

      {m.method !== "manual" && (
        <MeasureEvidence m={m} canAssess={canAssess} onChanged={onChanged} />
      )}

      <ManualEvidenceSection
        m={m}
        canUpload={canUpload}
        onChanged={onChanged}
      />

      <div className="drawer-section">
        <h3>Оценка</h3>
        {canAssess ? (
          <form
            className="form-stack drawer-form"
            onSubmit={(e) => {
              e.preventDefault();
              void save({
                status,
                owner_id: owner || null,
                comment: comment.trim() || null,
              });
            }}
          >
            <label className="field">
              <span>Статус</span>
              <select
                className="select"
                value={status}
                onChange={(e) => setStatus(e.target.value as MeasureStatus)}
              >
                {STATUS_ORDER.map((s) => (
                  <option key={s} value={s}>
                    {STATUS_LABELS[s]}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Ответственный</span>
              <select
                className="select"
                value={owner}
                onChange={(e) => setOwner(e.target.value)}
              >
                <option value="">не назначен</option>
                {members.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.display_name}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Комментарий</span>
              <textarea
                className="textarea"
                rows={2}
                maxLength={4000}
                value={comment}
                onChange={(e) => setComment(e.target.value)}
              />
            </label>
            <div className="actions">
              <button
                type="submit"
                className="btn btn-primary btn-sm"
                disabled={busy || !assessDirty}
              >
                Сохранить оценку
              </button>
            </div>
          </form>
        ) : (
          <dl className="props">
            <dt>Ответственный</dt>
            <dd>
              {m.owner_name ?? <span className="muted">не назначен</span>}
            </dd>
            <dt>Комментарий</dt>
            <dd>{m.comment ?? <span className="muted">—</span>}</dd>
          </dl>
        )}
      </div>

      <ConfirmSection m={m} canAssess={canAssess} onChanged={onChanged} />
    </Drawer>
  );
}
