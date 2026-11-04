import { FolderOpen, Globe, Plus, Server } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { Pager } from "../components/Pager";
import { ErrorAlert, Loading } from "../components/Status";
import { apiPage, apiSend, query } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDateTime } from "../lib/format";
import {
  DEFAULT_REGIME,
  KIND_HINTS,
  KIND_LABELS,
  REGIME_LABELS,
  type Kind,
  type ObjectBrief,
  type ObjectFull,
  type Regime,
} from "../lib/objects";
import { useProject } from "../lib/project";

const LIMIT = 50;

const STATUS_FILTERS: [string, string][] = [
  ["active", "Действующие"],
  ["archived", "В архиве"],
  ["", "Все"],
];

export function ObjectsPage() {
  const { can } = useAuth();
  const { current } = useProject();
  const navigate = useNavigate();
  const [items, setItems] = useState<ObjectBrief[] | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [status, setStatus] = useState("active");
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const projectId = current?.id;

  const load = useCallback(() => {
    if (!projectId) return;
    setError(null);
    apiPage<ObjectBrief>(
      `/projects/${projectId}/objects${query({ status, q: q.trim(), limit: LIMIT, offset })}`,
    )
      .then((p) => {
        setItems(p.items);
        setTotal(p.total);
      })
      .catch((e: Error) => setError(e.message));
  }, [projectId, status, q, offset]);

  useEffect(load, [load]);

  if (!current) {
    return (
      <>
        <div className="page-head">
          <div>
            <div className="crumbs">Аттестация</div>
            <h1>Объекты</h1>
          </div>
        </div>
        <section className="card">
          <EmptyState
            icon={<FolderOpen size={21} />}
            title="Нет проекта"
            text="Объекты живут внутри проекта. Выберите или создайте проект."
            action={
              <Link className="btn btn-primary" to="/projects">
                К проектам
              </Link>
            }
          />
        </section>
      </>
    );
  }

  const edit = can("objects.edit") && current.status === "active";

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            {current.client} · {current.name}
          </div>
          <h1>Объекты</h1>
        </div>
        {edit && (
          <div className="actions">
            <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
              <Plus size={15} />
              Новый объект
            </button>
          </div>
        )}
      </div>

      <div className="toolbar">
        <div className="chips" role="group" aria-label="Состояние">
          {STATUS_FILTERS.map(([value, label]) => (
            <button
              key={value}
              type="button"
              className="chip"
              aria-pressed={status === value}
              onClick={() => {
                setStatus(value);
                setOffset(0);
              }}
            >
              {label}
            </button>
          ))}
        </div>
        <input
          className="input toolbar-search"
          type="search"
          placeholder="Название, адрес или имя хоста"
          aria-label="Поиск объектов"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setOffset(0);
          }}
        />
      </div>

      {error && <ErrorAlert message={error} onRetry={load} />}

      <section className="card">
        {items === null && !error && <Loading />}
        {items?.length === 0 && (
          <EmptyState
            icon={<Server size={21} />}
            title={q || status !== "active" ? "Ничего не найдено" : "Объектов пока нет"}
            text={
              edit
                ? "Объект — информационная система заказчика: ГИС, ИСПДн или объект КИИ."
                : "Объекты проекта заводит методист."
            }
            action={
              edit && !q ? (
                <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
                  <Plus size={15} />
                  Новый объект
                </button>
              ) : undefined
            }
          />
        )}
        {items && items.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Объект</th>
                  <th>Вид</th>
                  <th>Режим</th>
                  <th className="num">Хосты</th>
                  <th className="num">Сегменты</th>
                  <th>Интернет</th>
                  <th>Изменён</th>
                  <th>Состояние</th>
                </tr>
              </thead>
              <tbody>
                {items.map((o) => (
                  <tr key={o.id} className="clickable" onClick={() => navigate(`/objects/${o.id}`)}>
                    <td>
                      <Link to={`/objects/${o.id}`} className="cell-title">
                        {o.name}
                      </Link>
                    </td>
                    <td>
                      <span className="tag" title={KIND_HINTS[o.kind]}>
                        {KIND_LABELS[o.kind]}
                      </span>
                    </td>
                    <td className="nowrap">{o.regime ? `№${o.regime}` : "—"}</td>
                    <td className="num">{o.host_count}</td>
                    <td className="num">{o.segment_count}</td>
                    <td>{o.internet ? <Globe size={15} aria-label="Подключён" /> : <span className="muted">нет</span>}</td>
                    <td className="nowrap">{formatDateTime(o.updated_at)}</td>
                    <td>
                      {o.status === "active" ? (
                        <span className="pill pill-ok">Действует</span>
                      ) : (
                        <span className="pill pill-muted">В архиве</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <Pager total={total} limit={LIMIT} offset={offset} onChange={setOffset} />
      </section>

      {creating && (
        <CreateObjectDialog
          projectId={current.id}
          onClose={() => setCreating(false)}
          onSaved={(o) => navigate(`/objects/${o.id}`)}
        />
      )}
    </>
  );
}

function CreateObjectDialog({
  projectId,
  onClose,
  onSaved,
}: {
  projectId: string;
  onClose: () => void;
  onSaved: (o: ObjectFull) => void;
}) {
  const [kind, setKind] = useState<Kind>("gis");
  const [regime, setRegime] = useState<Regime | "">("117");
  const [name, setName] = useState("");
  const [purpose, setPurpose] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onSaved(
        await apiSend<ObjectFull>("POST", `/projects/${projectId}/objects`, {
          kind,
          name,
          regime: regime || null,
          purpose: purpose || null,
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось создать объект");
      setBusy(false);
    }
  }

  const formId = "object-create";
  return (
    <Modal
      title="Новый объект"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={busy}>
            Создать
          </button>
        </>
      }
    >
      <form id={formId} className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <div className="form-row">
          <label className="field">
            <span>Вид объекта</span>
            <select
              className="select"
              value={kind}
              onChange={(e) => {
                const k = e.target.value as Kind;
                setKind(k);
                setRegime(DEFAULT_REGIME[k] ?? "");
              }}
            >
              {(Object.keys(KIND_LABELS) as Kind[]).map((k) => (
                <option key={k} value={k}>
                  {KIND_LABELS[k]}
                </option>
              ))}
            </select>
            <small>{KIND_HINTS[kind]}</small>
          </label>
          <RegimeField kind={kind} value={regime} onChange={setRegime} />
        </div>
        <label className="field">
          <span>Наименование</span>
          <input
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="ГИС «Учёт обращений граждан»"
            required
          />
        </label>
        <label className="field">
          <span>Назначение</span>
          <textarea className="textarea" value={purpose} onChange={(e) => setPurpose(e.target.value)} />
          <small>Описание, состав и границы можно заполнить позже в карточке объекта</small>
        </label>
      </form>
    </Modal>
  );
}

export function RegimeField({
  kind,
  value,
  onChange,
}: {
  kind: Kind;
  value: Regime | "";
  onChange: (r: Regime | "") => void;
}) {
  return (
    <label className="field">
      <span>Нормативный режим</span>
      <select className="select" value={value} onChange={(e) => onChange(e.target.value as Regime | "")}>
        {kind === "other" && <option value="">Не выбран</option>}
        {(Object.keys(REGIME_LABELS) as Regime[]).map((r) => (
          <option key={r} value={r}>
            {REGIME_LABELS[r]}
          </option>
        ))}
      </select>
      <small>Определяет базовый набор мер и вид классификации</small>
    </label>
  );
}
