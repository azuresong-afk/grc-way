import {
  Archive,
  ArchiveRestore,
  Globe,
  Link2,
  Pencil,
  Plus,
  RefreshCw,
  Server,
  Trash2,
  Layers,
  DownloadCloud,
  Calculator,
  Tags,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { apiGet, apiSend } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDateTime } from "../lib/format";
import {
  compareAddress,
  CRITICALITY_LABELS,
  DIRECTION_LABELS,
  KIND_HINTS,
  KIND_LABELS,
  REGIME_LABELS,
  looksLikeIp,
  INTERNET_LABELS,
  internetKey,
  inventoryGaps,
  type AssetsResponse,
  type ComponentType,
  type Host,
  type Inventory,
  type Interconnection,
  type Kind,
  type ObjectFull,
  type Regime,
  type Responsible,
  type Segment,
  type SyncResult,
} from "../lib/objects";
import { useProject } from "../lib/project";
import { ClassificationTab } from "./ClassificationTab";
import { MeasuresTab } from "./MeasuresTab";
import { SziTab } from "./SziTab";
import { ThreatModelTab } from "./ThreatModelTab";
import { VulnsTab } from "./VulnsTab";
import { RegimeField } from "./ObjectsPage";
import { BulkTypeDialog, InfrDialog, InventoryCard, TypeChips, TypePicker, useComponentTypes } from "./InventoryParts";

type Tab = "description" | "classification" | "measures" | "threats" | "vulns" | "szi" | "composition";
const TABS: Tab[] = ["description", "classification", "measures", "threats", "vulns", "szi", "composition"];

export function ObjectPage() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const { current, projects, select } = useProject();
  const [params, setParams] = useSearchParams();
  const tab: Tab = TABS.find((t) => t === params.get("tab")) ?? "description";
  const [obj, setObj] = useState<ObjectFull | null>(null);
  const [hosts, setHosts] = useState<Host[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);

  const load = useCallback(() => {
    setError(null);
    apiGet<ObjectFull>(`/objects/${id}`)
      .then(setObj)
      .catch((e: Error) => setError(e.message));
    apiGet<Host[]>(`/objects/${id}/hosts`)
      .then(setHosts)
      .catch((e: Error) => setError(e.message));
  }, [id]);

  useEffect(load, [load]);

  // Открытый объект делает свой проект текущим в верхней полосе.
  const ownProject = obj?.project_id;
  const known = projects.some((p) => p.id === ownProject);
  useEffect(() => {
    if (ownProject && known && current?.id !== ownProject) select(ownProject);
  }, [ownProject, known, current?.id, select]);

  const reloadObject = useCallback(() => {
    apiGet<ObjectFull>(`/objects/${id}`)
      .then(setObj)
      .catch((e: Error) => setError(e.message));
  }, [id]);

  function setTab(t: Tab) {
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (t === "description") next.delete("tab");
        else next.set("tab", t);
        return next;
      },
      { replace: true },
    );
  }

  async function toggleArchive() {
    if (!obj) return;
    try {
      setObj(
        await apiSend<ObjectFull>("PATCH", `/objects/${obj.id}`, {
          status: obj.status === "active" ? "archived" : "active",
        }),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось изменить объект");
    }
  }

  if (error && !obj) return <ErrorAlert message={error} onRetry={load} />;
  if (!obj) return <Loading />;

  // Проекты в архиве в верхнюю полосу не попадают: их объекты только для просмотра.
  const canEdit = can("objects.edit") && known;
  const editable = canEdit && obj.status === "active";

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            <Link to="/objects">Объекты</Link> / {KIND_LABELS[obj.kind]}
          </div>
          <h1>{obj.name}</h1>
        </div>
        {canEdit && (
          <div className="actions">
            <button type="button" className="btn" onClick={toggleArchive}>
              {obj.status === "active" ? <Archive size={15} /> : <ArchiveRestore size={15} />}
              {obj.status === "active" ? "В архив" : "Вернуть из архива"}
            </button>
            {editable && (
              <button type="button" className="btn btn-primary" onClick={() => setEditing(true)}>
                <Pencil size={15} />
                Изменить
              </button>
            )}
          </div>
        )}
      </div>

      {error && <ErrorAlert message={error} />}
      {obj.status === "archived" && (
        <div className="alert alert-info">
          <span className="alert-text">Объект в архиве: описание и состав только для просмотра.</span>
        </div>
      )}

      <div className="tabs" role="tablist" aria-label="Разделы объекта">
        <button
          type="button"
          role="tab"
          className="tab"
          aria-selected={tab === "description"}
          onClick={() => setTab("description")}
        >
          Описание
        </button>
        <button
          type="button"
          role="tab"
          className="tab"
          aria-selected={tab === "classification"}
          onClick={() => setTab("classification")}
        >
          Классификация
          {obj.classification && (
            <span className={`count${obj.classification.status === "draft" ? " count-warn" : ""}`}>
              {obj.classification.short}
            </span>
          )}
        </button>
        <button
          type="button"
          role="tab"
          className="tab"
          aria-selected={tab === "measures"}
          onClick={() => setTab("measures")}
        >
          Меры
        </button>
        <button
          type="button"
          role="tab"
          className="tab"
          aria-selected={tab === "threats"}
          onClick={() => setTab("threats")}
        >
          Модель угроз
        </button>
        <button
          type="button"
          role="tab"
          className="tab"
          aria-selected={tab === "vulns"}
          onClick={() => setTab("vulns")}
        >
          Уязвимости
        </button>
        <button type="button" role="tab" className="tab" aria-selected={tab === "szi"} onClick={() => setTab("szi")}>
          СЗИ
        </button>
        <button
          type="button"
          role="tab"
          className="tab"
          aria-selected={tab === "composition"}
          onClick={() => setTab("composition")}
        >
          Состав
          <span className="count">{obj.host_count}</span>
        </button>
      </div>

      {tab === "description" && <DescriptionTab obj={obj} />}
      {tab === "classification" && (
        <ClassificationTab obj={obj} editable={known && obj.status === "active"} onChanged={reloadObject} />
      )}
      {tab === "measures" && (
        <MeasuresTab obj={obj} editable={known && obj.status === "active"} onChanged={reloadObject} />
      )}
      {tab === "threats" && <ThreatModelTab obj={obj} editable={known && obj.status === "active"} />}
      {tab === "vulns" && <VulnsTab obj={obj} editable={known && obj.status === "active"} />}
      {tab === "szi" && <SziTab obj={obj} editable={known && obj.status === "active"} />}
      {tab === "composition" && (
        <CompositionTab
          obj={obj}
          hosts={hosts}
          editable={editable}
          onHosts={(h) => {
            setHosts(h);
            reloadObject();
          }}
          onSegments={reloadObject}
        />
      )}

      {editing && (
        <ObjectDialog
          obj={obj}
          onClose={() => setEditing(false)}
          onSaved={(o) => {
            setObj(o);
            setEditing(false);
          }}
        />
      )}
    </>
  );
}

// ---------- Описание ----------

function Text({ value }: { value: string | null }) {
  return value ? <span className="prewrap">{value}</span> : <span className="muted">не заполнено</span>;
}

function DescriptionTab({ obj }: { obj: ObjectFull }) {
  return (
    <>
      <div className="row-phi">
        <section className="card">
          <div className="card-head">
            <h2>Описание</h2>
            {obj.status === "active" ? (
              <span className="pill pill-ok">Действует</span>
            ) : (
              <span className="pill pill-muted">В архиве</span>
            )}
          </div>
          <dl className="props card-pad">
            <dt>Вид</dt>
            <dd>
              {KIND_LABELS[obj.kind]} <span className="muted">· {KIND_HINTS[obj.kind]}</span>
            </dd>
            <dt>Режим</dt>
            <dd>{obj.regime ? REGIME_LABELS[obj.regime] : <span className="muted">не выбран</span>}</dd>
            <dt>Назначение</dt>
            <dd>
              <Text value={obj.purpose} />
            </dd>
            <dt>Границы</dt>
            <dd>
              <Text value={obj.boundaries} />
            </dd>
            <dt>Интернет</dt>
            <dd>
              {obj.internet ? (
                <span className="pill pill-warn">
                  <Globe size={13} /> Подключён
                </span>
              ) : (
                "Не подключён"
              )}
            </dd>
            <dt>Изменён</dt>
            <dd>{formatDateTime(obj.updated_at)}</dd>
          </dl>
        </section>

        <section className="card">
          <div className="card-head">
            <h2>Ответственные</h2>
          </div>
          {obj.responsible.length === 0 ? (
            <p className="card-pad muted">Не назначены</p>
          ) : (
            <ul className="member-list">
              {obj.responsible.map((r, i) => (
                <li key={i}>
                  <span className="cell-title">{r.name}</span>
                  <span className="cell-sub">
                    {[r.role, r.position, r.phone, r.email].filter(Boolean).join(" · ") || "—"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section className="card">
        <div className="card-head">
          <h2>Взаимодействие с другими системами</h2>
        </div>
        {obj.interconnections.length === 0 ? (
          <p className="card-pad muted">Не указано</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Система</th>
                  <th>Владелец</th>
                  <th>Обмен</th>
                  <th>Канал</th>
                  <th>Описание</th>
                </tr>
              </thead>
              <tbody>
                {obj.interconnections.map((x, i) => (
                  <tr key={i}>
                    <td className="cell-title">{x.system}</td>
                    <td>{x.owner ?? "—"}</td>
                    <td className="nowrap">{DIRECTION_LABELS[x.direction]}</td>
                    <td>{x.channel ?? "—"}</td>
                    <td className="prewrap">{x.description ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

function ObjectDialog({
  obj,
  onClose,
  onSaved,
}: {
  obj: ObjectFull;
  onClose: () => void;
  onSaved: (o: ObjectFull) => void;
}) {
  const [kind, setKind] = useState<Kind>(obj.kind);
  const [regime, setRegime] = useState<Regime | "">(obj.regime ?? "");
  const [name, setName] = useState(obj.name);
  const [purpose, setPurpose] = useState(obj.purpose ?? "");
  const [boundaries, setBoundaries] = useState(obj.boundaries ?? "");
  const [internet, setInternet] = useState(obj.internet);
  const [responsible, setResponsible] = useState<Responsible[]>(obj.responsible);
  const [links, setLinks] = useState<Interconnection[]>(obj.interconnections);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const blank = (s: string | null | undefined) => (s && s.trim() ? s.trim() : null);
    try {
      onSaved(
        await apiSend<ObjectFull>("PATCH", `/objects/${obj.id}`, {
          kind,
          regime: regime || null,
          name,
          purpose: blank(purpose),
          boundaries: blank(boundaries),
          internet,
          responsible: responsible
            .filter((r) => r.name.trim())
            .map((r) => ({
              name: r.name.trim(),
              role: blank(r.role),
              position: blank(r.position),
              phone: blank(r.phone),
              email: blank(r.email),
            })),
          interconnections: links
            .filter((x) => x.system.trim())
            .map((x) => ({
              system: x.system.trim(),
              owner: blank(x.owner),
              direction: x.direction,
              channel: blank(x.channel),
              description: blank(x.description),
            })),
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось сохранить");
      setBusy(false);
    }
  }

  const setR = (i: number, patch: Partial<Responsible>) =>
    setResponsible((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const setL = (i: number, patch: Partial<Interconnection>) =>
    setLinks((ls) => ls.map((l, j) => (j === i ? { ...l, ...patch } : l)));

  const formId = "object-edit";
  return (
    <Modal
      title="Описание объекта"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={busy}>
            Сохранить
          </button>
        </>
      }
    >
      <form id={formId} className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <label className="field">
          <span>Наименование</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} required />
        </label>
        <div className="form-row">
          <label className="field">
            <span>Вид объекта</span>
            <select
              className="select"
              value={kind}
              onChange={(e) => {
                const k = e.target.value as Kind;
                setKind(k);
                if (k !== "other" && !regime) setRegime(k === "gis" ? "117" : k === "ispdn" ? "21" : "239");
              }}
            >
              {(Object.keys(KIND_LABELS) as Kind[]).map((k) => (
                <option key={k} value={k}>
                  {KIND_LABELS[k]}
                </option>
              ))}
            </select>
          </label>
          <RegimeField kind={kind} value={regime} onChange={setRegime} />
        </div>
        <label className="field">
          <span>Назначение</span>
          <textarea className="textarea" value={purpose} onChange={(e) => setPurpose(e.target.value)} />
        </label>
        <label className="field">
          <span>Границы</span>
          <textarea
            className="textarea"
            value={boundaries}
            onChange={(e) => setBoundaries(e.target.value)}
            placeholder="Площадки, контролируемая зона, точки подключения к внешним сетям"
          />
        </label>
        <label className="check">
          <input type="checkbox" checked={internet} onChange={(e) => setInternet(e.target.checked)} />
          <span>
            <b>Подключён к интернету</b>
            <small>Учитывается при классификации и в модели угроз</small>
          </span>
        </label>

        <fieldset className="rows-editor">
          <legend>Ответственные</legend>
          {responsible.map((r, i) => (
            <div key={i} className="rows-editor-row">
              <input
                className="input"
                aria-label="ФИО"
                placeholder="ФИО"
                value={r.name}
                onChange={(e) => setR(i, { name: e.target.value })}
              />
              <input
                className="input"
                aria-label="Роль"
                placeholder="Роль (администратор безопасности…)"
                value={r.role ?? ""}
                onChange={(e) => setR(i, { role: e.target.value })}
              />
              <input
                className="input"
                aria-label="Должность"
                placeholder="Должность"
                value={r.position ?? ""}
                onChange={(e) => setR(i, { position: e.target.value })}
              />
              <button
                type="button"
                className="icon-btn"
                aria-label="Убрать ответственного"
                onClick={() => setResponsible((rs) => rs.filter((_, j) => j !== i))}
              >
                <Trash2 size={15} />
              </button>
            </div>
          ))}
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            onClick={() => setResponsible((rs) => [...rs, { name: "" }])}
          >
            <Plus size={15} /> Добавить ответственного
          </button>
        </fieldset>

        <fieldset className="rows-editor">
          <legend>Взаимодействие с другими системами</legend>
          {links.map((l, i) => (
            <div key={i} className="rows-editor-row">
              <input
                className="input"
                aria-label="Система"
                placeholder="Система (СМЭВ, ЕСИА…)"
                value={l.system}
                onChange={(e) => setL(i, { system: e.target.value })}
              />
              <select
                className="select"
                aria-label="Направление обмена"
                value={l.direction}
                onChange={(e) =>
                  setL(i, {
                    direction: e.target.value as Interconnection["direction"],
                  })
                }
              >
                {Object.entries(DIRECTION_LABELS).map(([v, label]) => (
                  <option key={v} value={v}>
                    {label}
                  </option>
                ))}
              </select>
              <input
                className="input"
                aria-label="Канал"
                placeholder="Канал (VipNet, защищённый канал…)"
                value={l.channel ?? ""}
                onChange={(e) => setL(i, { channel: e.target.value })}
              />
              <button
                type="button"
                className="icon-btn"
                aria-label="Убрать систему"
                onClick={() => setLinks((ls) => ls.filter((_, j) => j !== i))}
              >
                <Trash2 size={15} />
              </button>
            </div>
          ))}
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            onClick={() => setLinks((ls) => [...ls, { system: "", direction: "both" }])}
          >
            <Plus size={15} /> Добавить систему
          </button>
        </fieldset>
      </form>
    </Modal>
  );
}

// ---------- Состав ----------

function hostsPayload(hosts: Host[]) {
  return {
    items: hosts.map((h) => ({
      address: h.address,
      hostname: h.hostname,
      role: h.role,
      segment_id: h.segment_id,
      component_types: h.component_types,
      internet_exposed: h.internet_exposed,
    })),
  };
}

function CompositionTab({
  obj,
  hosts,
  editable,
  onHosts,
  onSegments,
}: {
  obj: ObjectFull;
  hosts: Host[] | null;
  editable: boolean;
  onHosts: (h: Host[]) => void;
  onSegments: () => void;
}) {
  const [segmentFilter, setSegmentFilter] = useState("");
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [hostDialog, setHostDialog] = useState<Host | "new" | null>(null);
  const [assets, setAssets] = useState(false);
  const [segments, setSegments] = useState(false);
  const types = useComponentTypes();
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [gapsOnly, setGapsOnly] = useState(false);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [bulkType, setBulkType] = useState(false);
  const [infr, setInfr] = useState<string[] | null>(null);

  useEffect(() => {
    if (hosts === null) return;
    apiGet<Inventory>(`/objects/${obj.id}/inventory`).then(setInventory, () => setInventory(null));
    // Выбор переживает обновление состава только для оставшихся адресов.
    setPicked((prev) => {
      const left = new Set(hosts.map((h) => h.address));
      const next = new Set([...prev].filter((a) => left.has(a)));
      return next.size === prev.size ? prev : next;
    });
  }, [hosts, obj.id, obj.internet]);

  const segmentName = useMemo(() => new Map(obj.segments.map((s) => [s.id, s.name])), [obj.segments]);

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (hosts ?? []).filter(
      (h) =>
        (segmentFilter === "" || (segmentFilter === "none" ? h.segment_id === null : h.segment_id === segmentFilter)) &&
        (!needle ||
          h.address.startsWith(needle) ||
          (h.hostname ?? "").toLowerCase().includes(needle) ||
          (h.role ?? "").toLowerCase().includes(needle)) &&
        (!gapsOnly || inventoryGaps(h).length > 0),
    );
  }, [hosts, segmentFilter, q, gapsOnly]);

  function togglePick(addresses: string[], on: boolean) {
    setPicked((prev) => {
      const next = new Set(prev);
      for (const a of addresses) {
        if (on) next.add(a);
        else next.delete(a);
      }
      return next;
    });
  }

  async function patchPicked(patch: Partial<Host>): Promise<boolean> {
    return save((hosts ?? []).map((x) => (picked.has(x.address) ? { ...x, ...patch } : x)));
  }

  async function save(next: Host[]): Promise<boolean> {
    setError(null);
    try {
      onHosts(await apiSend<Host[]>("PUT", `/objects/${obj.id}/hosts`, hostsPayload(next)));
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось сохранить состав");
      return false;
    }
  }

  async function refresh() {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const r = await apiSend<SyncResult>("POST", `/objects/${obj.id}/hosts/sync-from-scanner`, {});
      onHosts(r.hosts);
      setNotice(syncSummary(r));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось обновить из «Сканера»");
    } finally {
      setBusy(false);
    }
  }

  const linked = obj.scanner_engagement_id !== null;
  const unassigned = (hosts ?? []).filter((h) => h.segment_id === null).length;

  return (
    <>
      {!linked && (
        <div className="alert alert-info">
          <Link2 size={15} />
          <span className="alert-text">
            Проект не связан со «Сканером» — хосты можно добавить вручную. Номер engagement задаётся в{" "}
            <Link to={`/projects/${obj.project_id}`}>карточке проекта</Link>.
          </span>
        </div>
      )}
      {error && <ErrorAlert message={error} />}
      {notice && (
        <div className="alert alert-ok" role="status">
          <span className="alert-text">{notice}</span>
        </div>
      )}

      <section className="card">
        <div className="card-head">
          <h2>Сегменты</h2>
          {editable && (
            <button type="button" className="btn btn-sm" onClick={() => setSegments(true)}>
              <Layers size={15} />
              Изменить
            </button>
          )}
        </div>
        {obj.segments.length === 0 ? (
          <p className="card-pad muted">
            Сегментов нет. При добавлении хостов из «Сканера» они создаются по группам активов.
          </p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Сегмент</th>
                  <th>Описание</th>
                  <th>Группа «Сканера»</th>
                  <th className="num">Хосты</th>
                </tr>
              </thead>
              <tbody>
                {obj.segments.map((s) => (
                  <tr key={s.id}>
                    <td className="cell-title">{s.name}</td>
                    <td className="prewrap">{s.description ?? "—"}</td>
                    <td>{s.scanner_group ?? <span className="muted">—</span>}</td>
                    <td className="num">{s.host_count}</td>
                  </tr>
                ))}
                {unassigned > 0 && (
                  <tr>
                    <td className="muted">Без сегмента</td>
                    <td />
                    <td />
                    <td className="num">{unassigned}</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <InventoryCard
        inventory={inventory}
        onShowGaps={() => {
          setGapsOnly(true);
          setSegmentFilter("");
          setQ("");
        }}
      />

      <section className="card">
        <div className="card-head">
          <h2>Хосты</h2>
          {editable && (
            <div className="actions">
              {linked && (
                <button type="button" className="btn btn-sm" onClick={refresh} disabled={busy}>
                  <RefreshCw size={15} className={busy ? "spin" : undefined} />
                  Обновить из «Сканера»
                </button>
              )}
              {linked && (
                <button type="button" className="btn btn-sm" onClick={() => setAssets(true)}>
                  <DownloadCloud size={15} />
                  Из активов «Сканера»
                </button>
              )}
              <button type="button" className="btn btn-sm btn-primary" onClick={() => setHostDialog("new")}>
                <Plus size={15} />
                Добавить вручную
              </button>
            </div>
          )}
        </div>
        <div className="card-pad toolbar">
          <select
            className="select toolbar-select"
            aria-label="Сегмент"
            value={segmentFilter}
            onChange={(e) => setSegmentFilter(e.target.value)}
          >
            <option value="">Все сегменты</option>
            {obj.segments.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
            <option value="none">Без сегмента</option>
          </select>
          <input
            className="input toolbar-search"
            type="search"
            placeholder="Адрес, имя или роль"
            aria-label="Поиск хостов"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <label className="check-inline">
            <input type="checkbox" checked={gapsOnly} onChange={(e) => setGapsOnly(e.target.checked)} />
            Не хватает типа или доступности
          </label>
          <span className="muted">
            {linked ? `«Сканер»: engagement №${obj.scanner_engagement_id}` : "«Сканер» не связан"}
            {obj.scanner_synced_at && ` · сверено ${formatDateTime(obj.scanner_synced_at)}`}
          </span>
        </div>
        {hosts === null && <Loading />}
        {hosts?.length === 0 && (
          <EmptyState
            icon={<Server size={21} />}
            title="Хостов нет"
            text={
              linked
                ? "Добавьте хосты из активов «Сканера» или вручную по IP-адресу."
                : "Добавьте хосты вручную по IP-адресу."
            }
          />
        )}
        {hosts && hosts.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th className="cell-check">
                    <input
                      type="checkbox"
                      aria-label="Выбрать все показанные"
                      checked={shown.length > 0 && shown.every((h) => picked.has(h.address))}
                      onChange={(e) =>
                        togglePick(
                          shown.map((h) => h.address),
                          e.target.checked,
                        )
                      }
                    />
                  </th>
                  <th>Адрес</th>
                  <th>Имя и роль</th>
                  <th>Сегмент</th>
                  <th>Тип компонента</th>
                  <th>Из «Интернета»</th>
                  <th>ОС</th>
                  <th>Критичность</th>
                  <th>Источник</th>
                  <th>Виден в «Сканере»</th>
                  {editable && <th className="cell-actions" aria-label="Действия" />}
                </tr>
              </thead>
              <tbody>
                {shown.map((h) => (
                  <tr key={h.id} className={picked.has(h.address) ? "selected" : undefined}>
                    <td className="cell-check">
                      <input
                        type="checkbox"
                        aria-label={`Выбрать ${h.address}`}
                        checked={picked.has(h.address)}
                        onChange={(e) => togglePick([h.address], e.target.checked)}
                      />
                    </td>
                    <td className="mono nowrap">{h.address}</td>
                    <td>
                      <div className="cell-title">{h.hostname ?? <span className="muted">—</span>}</div>
                      {h.role && <div className="cell-sub">{h.role}</div>}
                    </td>
                    <td>
                      {editable ? (
                        <select
                          className="select select-sm"
                          aria-label={`Сегмент ${h.address}`}
                          value={h.segment_id ?? ""}
                          onChange={(e) =>
                            save(
                              (hosts ?? []).map((x) =>
                                x.id === h.id ? { ...x, segment_id: e.target.value || null } : x,
                              ),
                            )
                          }
                        >
                          <option value="">Без сегмента</option>
                          {obj.segments.map((s) => (
                            <option key={s.id} value={s.id}>
                              {s.name}
                            </option>
                          ))}
                        </select>
                      ) : (
                        ((h.segment_id && segmentName.get(h.segment_id)) ?? <span className="muted">—</span>)
                      )}
                    </td>
                    <td>
                      <TypeChips codes={h.component_types} types={types} />
                    </td>
                    <td>
                      {editable ? (
                        <select
                          className={`select select-sm${h.internet_exposed === null ? " select-warn" : ""}`}
                          aria-label={`Доступность из «Интернета» ${h.address}`}
                          value={internetKey(h.internet_exposed)}
                          onChange={(e) =>
                            save(
                              (hosts ?? []).map((x) =>
                                x.id === h.id
                                  ? {
                                      ...x,
                                      internet_exposed: fromInternetKey(e.target.value),
                                    }
                                  : x,
                              ),
                            )
                          }
                        >
                          {Object.entries(INTERNET_LABELS).map(([k, label]) => (
                            <option key={k} value={k}>
                              {label}
                            </option>
                          ))}
                        </select>
                      ) : h.internet_exposed === null ? (
                        <span className="pill pill-warn">не указано</span>
                      ) : (
                        INTERNET_LABELS[internetKey(h.internet_exposed)]
                      )}
                    </td>
                    <td>{h.os ?? <span className="muted">—</span>}</td>
                    <td>{h.criticality ? (CRITICALITY_LABELS[h.criticality] ?? h.criticality) : "—"}</td>
                    <td>
                      <div className="pill-stack">
                        {h.source === "scanner" ? (
                          <span className="pill pill-info">«Сканер»</span>
                        ) : (
                          <span className="pill pill-muted">Вручную</span>
                        )}
                        {h.source === "manual" && h.scanner_asset_id !== null && !h.scanner_missing && (
                          <span className="pill pill-info" title="Адрес найден среди активов «Сканера»">
                            связан
                          </span>
                        )}
                        {h.scanner_missing && (
                          <span
                            className="pill pill-warn"
                            title="При последней сверке адреса не было среди активов «Сканера»"
                          >
                            нет в «Сканере»
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="nowrap">{formatDateTime(h.last_seen_at)}</td>
                    {editable && (
                      <td className="cell-actions">
                        <button
                          type="button"
                          className="icon-btn"
                          aria-label={`Изменить ${h.address}`}
                          title="Изменить"
                          onClick={() => setHostDialog(h)}
                        >
                          <Pencil size={15} />
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
                {shown.length === 0 && (
                  <tr>
                    <td colSpan={editable ? 11 : 10} className="muted">
                      Под фильтр ничего не попало
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {picked.size > 0 && (
        <div className="apply-bar">
          <span>
            Выбрано хостов: <b>{picked.size}</b>
          </span>
          <div className="actions">
            {editable && (
              <>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => setBulkType(true)}
                  disabled={!types?.length}
                >
                  <Tags size={15} />
                  Тип компонента…
                </button>
                <select
                  className="select select-sm"
                  aria-label="Доступность из «Интернета» для выбранных"
                  value=""
                  onChange={(e) => {
                    if (e.target.value)
                      void patchPicked({
                        internet_exposed: fromInternetKey(e.target.value),
                      });
                  }}
                >
                  <option value="">Из «Интернета»…</option>
                  {Object.entries(INTERNET_LABELS).map(([k, label]) => (
                    <option key={k} value={k}>
                      {label}
                    </option>
                  ))}
                </select>
              </>
            )}
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={() => setInfr([...picked])}
              title="Считать выбранные хосты уязвимыми и показать K, L, P и I_infr"
            >
              <Calculator size={15} />
              Проверить I_infr
            </button>
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => setPicked(new Set())}>
              Снять выбор
            </button>
          </div>
        </div>
      )}
      {bulkType && types && (
        <BulkTypeDialog
          count={picked.size}
          types={types}
          onClose={() => setBulkType(false)}
          onApply={async (codes) => {
            const ok = await patchPicked({ component_types: codes });
            if (ok) setBulkType(false);
            return ok;
          }}
        />
      )}
      {infr && <InfrDialog objectId={obj.id} addresses={infr} onClose={() => setInfr(null)} />}
      {hostDialog && hosts && (
        <HostDialog
          host={hostDialog === "new" ? null : hostDialog}
          segments={obj.segments}
          types={types}
          hosts={hosts}
          onClose={() => setHostDialog(null)}
          onSave={async (next) => {
            const ok = await save(next);
            if (ok) setHostDialog(null);
            return ok;
          }}
        />
      )}
      {assets && (
        <AssetsDialog
          objectId={obj.id}
          onClose={() => setAssets(false)}
          onDone={(r) => {
            setAssets(false);
            onHosts(r.hosts);
            setNotice(syncSummary(r));
          }}
        />
      )}
      {segments && (
        <SegmentsDialog
          obj={obj}
          onClose={() => setSegments(false)}
          onSaved={() => {
            setSegments(false);
            onSegments();
            apiGet<Host[]>(`/objects/${obj.id}/hosts`).then(onHosts, () => undefined);
          }}
        />
      )}
    </>
  );
}

function plural(n: number, one: string, few: string, many: string): string {
  const m10 = n % 10;
  const m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
}

export function syncSummary(r: SyncResult): string {
  const parts: string[] = [];
  const n = (k: number) => `${k} ${plural(k, "хост", "хоста", "хостов")}`;
  if (r.added.length) parts.push(`добавлено ${n(r.added.length)}`);
  if (r.updated.length) parts.push(`обновлено ${n(r.updated.length)}`);
  if (r.linked.length) parts.push(`связано с активами ${n(r.linked.length)}`);
  if (r.segments_created.length) parts.push(`созданы сегменты: ${r.segments_created.join(", ")}`);
  if (r.missing.length) parts.push(`нет в «Сканере»: ${r.missing.join(", ")}`);
  return parts.length ? `Сверено со «Сканером»: ${parts.join("; ")}.` : "Сверено со «Сканером»: изменений нет.";
}

function HostDialog({
  host,
  segments,
  types,
  hosts,
  onClose,
  onSave,
}: {
  host: Host | null;
  segments: Segment[];
  types: ComponentType[] | null;
  hosts: Host[];
  onClose: () => void;
  onSave: (next: Host[]) => Promise<boolean>;
}) {
  const [address, setAddress] = useState(host?.address ?? "");
  const [hostname, setHostname] = useState(host?.hostname ?? "");
  const [role, setRole] = useState(host?.role ?? "");
  const [segmentId, setSegmentId] = useState(host?.segment_id ?? "");
  const [componentTypes, setComponentTypes] = useState<string[]>(host?.component_types ?? []);
  const [internet, setInternet] = useState(internetKey(host?.internet_exposed ?? null));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const addr = address.trim();
    if (!host && !looksLikeIp(addr)) {
      setError("Укажите IP-адрес: так хост сопоставляется с активами «Сканера»");
      return;
    }
    if (!host && hosts.some((h) => h.address === addr.toLowerCase())) {
      setError("Этот адрес уже в составе объекта");
      return;
    }
    const patch = {
      hostname: hostname.trim() || null,
      role: role.trim() || null,
      segment_id: segmentId || null,
      component_types: componentTypes.length ? componentTypes : null,
      internet_exposed: fromInternetKey(internet),
    };
    const next = host
      ? hosts.map((h) => (h.id === host.id ? { ...h, ...patch } : h))
      : [...hosts, { ...blankHost(addr), ...patch }];
    setBusy(true);
    if (!(await onSave(next))) setBusy(false);
  }

  async function remove() {
    if (!host) return;
    setBusy(true);
    if (!(await onSave(hosts.filter((h) => h.id !== host.id)))) setBusy(false);
  }

  const formId = "host-form";
  return (
    <Modal
      title={host ? `Хост ${host.address}` : "Новый хост"}
      onClose={onClose}
      footer={
        <>
          {host && (
            <button type="button" className="btn btn-danger" onClick={remove} disabled={busy}>
              <Trash2 size={15} /> Исключить из состава
            </button>
          )}
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={busy}>
            {host ? "Сохранить" : "Добавить"}
          </button>
        </>
      }
    >
      <form id={formId} className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <div className="form-row">
          <label className="field">
            <span>IP-адрес</span>
            <input
              className="input mono"
              value={address}
              onChange={(e) => setAddress(e.target.value)}
              disabled={host !== null}
              placeholder="10.10.1.10"
              required
            />
            {host?.source === "scanner" && <small>Хост из «Сканера»: ОС и критичность приходят оттуда</small>}
          </label>
          <label className="field">
            <span>Имя хоста</span>
            <input className="input" value={hostname} onChange={(e) => setHostname(e.target.value)} />
          </label>
        </div>
        <label className="field">
          <span>Роль в системе</span>
          <input
            className="input"
            value={role}
            onChange={(e) => setRole(e.target.value)}
            placeholder="Сервер СУБД, АРМ оператора, межсетевой экран…"
          />
        </label>
        <label className="field">
          <span>Сегмент</span>
          <select className="select" value={segmentId} onChange={(e) => setSegmentId(e.target.value)}>
            <option value="">Без сегмента</option>
            {segments.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Доступен из сети «Интернет»</span>
          <select
            className="select"
            value={internet}
            onChange={(e) => setInternet(e.target.value as keyof typeof INTERNET_LABELS)}
          >
            {Object.entries(INTERNET_LABELS).map(([k, label]) => (
              <option key={k} value={k}>
                {label}
              </option>
            ))}
          </select>
          <small>Показатель P Методики 2025: влияние на защищённость периметра</small>
        </label>
        <fieldset className="field">
          <legend className="field-legend">Тип компонента</legend>
          <small className="muted">
            Показатель K таблицы 1 Методики 2025. Можно отметить несколько — в расчёте берётся наибольшее.
          </small>
          {types === null ? (
            <Loading />
          ) : types.length === 0 ? (
            <span className="muted">Справочник Методики не загружен</span>
          ) : (
            <TypePicker types={types} value={componentTypes} onChange={setComponentTypes} />
          )}
        </fieldset>
      </form>
    </Modal>
  );
}

function blankHost(address: string): Host {
  return {
    id: `new-${address}`,
    address,
    hostname: null,
    role: null,
    segment_id: null,
    os: null,
    os_family: null,
    source: "manual",
    scanner_asset_id: null,
    scanner_groups: [],
    criticality: null,
    owner: null,
    last_seen_at: null,
    scanner_missing: false,
    synced_at: null,
    component_types: null,
    internet_exposed: null,
  };
}

function fromInternetKey(k: string): boolean | null {
  return k === "yes" ? true : k === "no" ? false : null;
}

function AssetsDialog({
  objectId,
  onClose,
  onDone,
}: {
  objectId: string;
  onClose: () => void;
  onDone: (r: SyncResult) => void;
}) {
  const [data, setData] = useState<AssetsResponse | null>(null);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [byGroup, setByGroup] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiGet<AssetsResponse>(`/objects/${objectId}/scanner/assets`)
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [objectId]);

  const free = useMemo(() => (data?.assets ?? []).filter((a) => !a.in_object), [data]);
  const groups = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const a of free)
      for (const g of a.groups.length ? a.groups : ["Без группы"]) {
        m.set(g, [...(m.get(g) ?? []), a.address]);
      }
    return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0], "ru"));
  }, [free]);

  function toggle(addresses: string[], on: boolean) {
    setChosen((prev) => {
      const next = new Set(prev);
      for (const a of addresses) {
        if (on) next.add(a);
        else next.delete(a);
      }
      return next;
    });
  }

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      onDone(
        await apiSend<SyncResult>("POST", `/objects/${objectId}/hosts/sync-from-scanner`, {
          addresses: [...chosen].sort(compareAddress),
          segments_from_groups: byGroup,
        }),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось добавить хосты");
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Хосты из активов «Сканера»"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" onClick={submit} disabled={busy || chosen.size === 0}>
            Добавить {chosen.size > 0 ? chosen.size : ""}
          </button>
        </>
      }
    >
      {error && <ErrorAlert message={error} />}
      {!data && !error && <Loading />}
      {data && (
        <div className="form-stack">
          <p className="muted">
            Проект «Сканера» №{data.engagement_id} · {data.source}. Хост сопоставляется по IP-адресу: повторное
            добавление не создаёт дубликатов.
          </p>
          {groups.length > 0 && (
            <div className="chips" role="group" aria-label="Выбрать группу целиком">
              {groups.map(([g, addrs]) => {
                const all = addrs.every((a) => chosen.has(a));
                return (
                  <button key={g} type="button" className="chip" aria-pressed={all} onClick={() => toggle(addrs, !all)}>
                    {g} <span className="count">{addrs.length}</span>
                  </button>
                );
              })}
            </div>
          )}
          <div className="asset-list">
            {data.assets.map((a) => (
              <label key={a.address} className="check">
                <input
                  type="checkbox"
                  checked={a.in_object || chosen.has(a.address)}
                  disabled={a.in_object}
                  onChange={(e) => toggle([a.address], e.target.checked)}
                />
                <span>
                  <b>
                    <span className="mono">{a.address}</span>
                    {a.hostname && ` · ${a.hostname}`}
                  </b>
                  <small>
                    {[a.groups.join(", ") || "без группы", a.os, a.in_object ? "уже в составе" : null]
                      .filter(Boolean)
                      .join(" · ")}
                    {a.other_objects.length > 0 && ` · также в: ${a.other_objects.join(", ")}`}
                  </small>
                </span>
              </label>
            ))}
            {data.assets.length === 0 && <p className="muted">В проекте «Сканера» нет активов.</p>}
          </div>
          <label className="check">
            <input type="checkbox" checked={byGroup} onChange={(e) => setByGroup(e.target.checked)} />
            <span>
              <b>Сегменты по группам «Сканера»</b>
              <small>Новые хосты попадут в сегмент с именем их группы; недостающие сегменты будут созданы</small>
            </span>
          </label>
        </div>
      )}
    </Modal>
  );
}

interface SegmentDraft {
  id?: string;
  name: string;
  description: string;
  scanner_group: string;
}

function SegmentsDialog({ obj, onClose, onSaved }: { obj: ObjectFull; onClose: () => void; onSaved: () => void }) {
  const [rows, setRows] = useState<SegmentDraft[]>(
    obj.segments.map((s) => ({
      id: s.id,
      name: s.name,
      description: s.description ?? "",
      scanner_group: s.scanner_group ?? "",
    })),
  );
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (i: number, patch: Partial<SegmentDraft>) =>
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiSend("PUT", `/objects/${obj.id}/segments`, {
        items: rows
          .filter((r) => r.name.trim())
          .map((r) => ({
            id: r.id,
            name: r.name.trim(),
            description: r.description.trim() || null,
            scanner_group: r.scanner_group.trim() || null,
          })),
      });
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось сохранить сегменты");
      setBusy(false);
    }
  }

  const removedHosts = obj.segments
    .filter((s) => !rows.some((r) => r.id === s.id))
    .reduce((n, s) => n + s.host_count, 0);

  const formId = "segments-form";
  return (
    <Modal
      title="Сегменты объекта"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={busy}>
            Сохранить
          </button>
        </>
      }
    >
      <form id={formId} className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <fieldset className="rows-editor">
          <legend>Название · описание · группа активов «Сканера»</legend>
          {rows.map((r, i) => (
            <div key={r.id ?? `new-${i}`} className="rows-editor-row">
              <input
                className="input"
                aria-label="Название сегмента"
                placeholder="ЛВС, ДМЗ, площадка…"
                value={r.name}
                onChange={(e) => set(i, { name: e.target.value })}
              />
              <input
                className="input"
                aria-label="Описание сегмента"
                placeholder="Описание"
                value={r.description}
                onChange={(e) => set(i, { description: e.target.value })}
              />
              <input
                className="input"
                aria-label="Группа «Сканера»"
                placeholder="Группа «Сканера»"
                value={r.scanner_group}
                onChange={(e) => set(i, { scanner_group: e.target.value })}
              />
              <button
                type="button"
                className="icon-btn"
                aria-label="Удалить сегмент"
                onClick={() => setRows((rs) => rs.filter((_, j) => j !== i))}
              >
                <Trash2 size={15} />
              </button>
            </div>
          ))}
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            onClick={() => setRows((rs) => [...rs, { name: "", description: "", scanner_group: "" }])}
          >
            <Plus size={15} /> Добавить сегмент
          </button>
        </fieldset>
        {removedHosts > 0 && (
          <div className="alert alert-warn">
            <span className="alert-text">
              Хосты удаляемых сегментов ({removedHosts}) останутся в составе без сегмента.
            </span>
          </div>
        )}
      </form>
    </Modal>
  );
}
