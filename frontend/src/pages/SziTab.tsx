import { AlertTriangle, Pencil, Plus, Search, ShieldCheck, Trash2 } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { ApiError, apiGet, apiSend } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDate } from "../lib/bdu";
import { formatNumber } from "../lib/format";
import type { ObjectMeasure } from "../lib/measures";
import type { ObjectFull } from "../lib/objects";
import {
  LEVEL_PILL,
  REGISTRY_MATCH,
  daysText,
  type Cert,
  type ObjectSzi,
  type SziList,
} from "../lib/szi";

function message(e: unknown, fallback: string): string {
  return e instanceof ApiError || e instanceof Error ? e.message : fallback;
}

export function CertCell({ s }: { s: ObjectSzi }) {
  if (!s.cert_number) return <span className="muted">нет</span>;
  const trust = s.effective_trust_level;
  const profiles = s.registry?.profiles ?? [];
  return (
    <>
      <span className="mono">№ {s.cert_number}</span>
      {trust && <span className="muted"> · УД {trust}</span>}
      {(profiles.length > 0 || s.protection_class) && (
        <div className="cell-sub mono">{profiles.length ? profiles.join(", ") : s.protection_class}</div>
      )}
      <div className="cell-sub">{REGISTRY_MATCH[s.registry_match]}</div>
    </>
  );
}

export function ValidCell({ s }: { s: ObjectSzi }) {
  if (!s.valid_to) return <span className="muted">—</span>;
  return (
    <>
      <span className="nowrap">{formatDate(s.valid_to)}</span>
      <div className={`cell-sub${s.level === "bad" || s.state === "expiring" ? " text-warn" : ""}`}>
        {daysText(s.days_left)}
        {s.valid_to_source === "manual" && " · введён вручную"}
      </div>
    </>
  );
}

export function StatePill({ s }: { s: ObjectSzi }) {
  return (
    <div className="pill-stack">
      <span className={`pill ${LEVEL_PILL[s.level]}`}>{s.state_title}</span>
      {s.support_ended && (
        <span className="pill pill-warn" title={`по реестру — ${formatDate(s.registry?.support_until ?? null)}`}>
          Поддержка окончена
        </span>
      )}
    </div>
  );
}

export function SziTab({ obj, editable }: { obj: ObjectFull; editable: boolean }) {
  const { can } = useAuth();
  const canEdit = editable && can("objects.edit");
  const [data, setData] = useState<SziList | null>(null);
  const [measures, setMeasures] = useState<ObjectMeasure[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<ObjectSzi | "new" | null>(null);
  const [removing, setRemoving] = useState<ObjectSzi | null>(null);

  const load = useCallback(() => {
    setError(null);
    apiGet<SziList>(`/objects/${obj.id}/szi`)
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [obj.id]);
  useEffect(load, [load]);
  useEffect(() => {
    apiGet<ObjectMeasure[]>(`/objects/${obj.id}/measures`)
      .then(setMeasures)
      .catch(() => setMeasures([]));
  }, [obj.id]);

  if (error && !data) return <ErrorAlert message={error} onRetry={load} />;
  if (!data) return <Loading />;
  const c = data.counts;

  return (
    <>
      {c.bad > 0 && (
        <div className="alert alert-danger" role="status">
          <AlertTriangle size={15} />
          <span className="alert-text">
            У {formatNumber(c.bad)} СЗИ сертификат недействителен: истёк срок, действие приостановлено или
            прекращено, либо сертификат исключён из реестра. Меры, которые они закрывают, нужно перепроверить.
          </span>
        </div>
      )}
      {c.expiring > 0 && (
        <div className="alert alert-warn" role="status">
          <AlertTriangle size={15} />
          <span className="alert-text">
            У {formatNumber(c.expiring)} СЗИ сертификат истекает в ближайшие {data.expiry_days} дн.
          </span>
        </div>
      )}
      {!data.registry_loaded && (
        <div className="alert alert-info">
          <span className="alert-text">
            Реестр сертифицированных СЗИ не загружен: сроки берутся из введённых вручную, сверить номера не с
            чем. <Link to="/refs/szi">Справочники → Реестр СЗИ</Link>
          </span>
        </div>
      )}

      <div className="kpi-row szi-kpis">
        <div className="card kpi">
          <span className="kpi-label">СЗИ на объекте</span>
          <span className={`kpi-value${c.total ? "" : " muted"}`}>{formatNumber(c.total)}</span>
          <span className="kpi-delta">
            {data.registry_version ? `реестр от ${formatDate(data.registry_version)}` : "реестр не загружен"}
          </span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">Недействительны</span>
          <span className={`kpi-value${c.bad ? " danger" : " muted"}`}>{formatNumber(c.bad)}</span>
          <span className="kpi-delta">истёк, приостановлен, исключён</span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">Истекают</span>
          <span className={`kpi-value${c.expiring ? " warn" : " muted"}`}>{formatNumber(c.expiring)}</span>
          <span className="kpi-delta">в ближайшие {data.expiry_days} дн.</span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">Проверить</span>
          <span className={`kpi-value${c.check ? " warn" : " muted"}`}>{formatNumber(c.check)}</span>
          <span className="kpi-delta">нет в реестре или срок не указан</span>
        </div>
      </div>

      <section className="card">
        <div className="card-head">
          <h2>Средства защиты информации</h2>
          {canEdit && (
            <button type="button" className="btn btn-primary btn-sm" onClick={() => setEditing("new")}>
              <Plus size={15} /> Добавить СЗИ
            </button>
          )}
        </div>
        {data.items.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck size={21} />}
            title="СЗИ не заведены"
            text="Добавьте средства защиты объекта с номерами сертификатов ФСТЭК: срок действия сверится с реестром, а в мерах будет видно, какое СЗИ их закрывает."
          />
        ) : (
          <div className="table-wrap">
            <table className="table szi-table">
              <thead>
                <tr>
                  <th>СЗИ</th>
                  <th>Сертификат</th>
                  <th>Действует до</th>
                  <th>Состояние</th>
                  <th>Закрывает меры</th>
                  {canEdit && <th className="cell-actions" aria-label="Действия" />}
                </tr>
              </thead>
              <tbody>
                {data.items.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <span className="cell-title">{s.name}</span>
                      <div className="cell-sub">
                        {[s.kind_title, s.vendor, s.version].filter(Boolean).join(" · ")}
                      </div>
                      {s.placement && <div className="cell-sub">{s.placement}</div>}
                    </td>
                    <td>
                      <CertCell s={s} />
                    </td>
                    <td>
                      <ValidCell s={s} />
                    </td>
                    <td>
                      <StatePill s={s} />
                      {s.notes.map((n) => (
                        <div key={n} className="cell-sub">
                          {n}
                        </div>
                      ))}
                    </td>
                    <td>
                      {s.measures.length === 0 ? (
                        <span className="muted">—</span>
                      ) : (
                        <div className="tag-list">
                          {s.measures.map((m) => (
                            <span
                              key={m.measure_id}
                              className={`tag${m.state === "in_set" ? "" : " tag-muted"}`}
                              title={
                                m.state === "missing"
                                  ? "Меры нет в наборе объекта"
                                  : m.state === "excluded"
                                    ? "Мера исключена при адаптации"
                                    : (m.title ?? undefined)
                              }
                            >
                              {m.measure_id}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    {canEdit && (
                      <td className="cell-actions">
                        <button
                          type="button"
                          className="icon-btn"
                          aria-label={`Изменить ${s.name}`}
                          onClick={() => setEditing(s)}
                        >
                          <Pencil size={15} />
                        </button>
                        <button
                          type="button"
                          className="icon-btn"
                          aria-label={`Удалить ${s.name}`}
                          onClick={() => setRemoving(s)}
                        >
                          <Trash2 size={15} />
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {editing && (
        <SziDialog
          objectId={obj.id}
          szi={editing === "new" ? null : editing}
          kinds={data.kinds}
          measures={measures ?? []}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            load();
          }}
        />
      )}
      {removing && (
        <RemoveDialog
          s={removing}
          onClose={() => setRemoving(null)}
          onDone={() => {
            setRemoving(null);
            load();
          }}
        />
      )}
    </>
  );
}

function RemoveDialog({ s, onClose, onDone }: { s: ObjectSzi; onClose: () => void; onDone: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Modal
      title="Удалить СЗИ"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="button"
            className="btn btn-danger"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await apiSend("DELETE", `/object-szi/${s.id}`);
                onDone();
              } catch (e) {
                setError(message(e, "Не удалось удалить"));
                setBusy(false);
              }
            }}
          >
            Удалить
          </button>
        </>
      }
    >
      <p>
        «{s.name}» пропадёт из реестра СЗИ объекта и из мер, которые оно закрывает. Запись об удалении останется в
        журнале аудита.
      </p>
      {error && <ErrorAlert message={error} />}
    </Modal>
  );
}

function SziDialog({
  objectId,
  szi,
  kinds,
  measures,
  onClose,
  onSaved,
}: {
  objectId: string;
  szi: ObjectSzi | null;
  kinds: Record<string, string>;
  measures: ObjectMeasure[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(szi?.name ?? "");
  const [kind, setKind] = useState(szi?.kind ?? "fw");
  const [vendor, setVendor] = useState(szi?.vendor ?? "");
  const [version, setVersion] = useState(szi?.version ?? "");
  const [cert, setCert] = useState(szi?.cert_number ?? "");
  const [validTo, setValidTo] = useState(szi?.cert_valid_to ?? "");
  const [trust, setTrust] = useState(szi?.trust_level ? String(szi.trust_level) : "");
  const [cls, setCls] = useState(szi?.protection_class ?? "");
  const [placement, setPlacement] = useState(szi?.placement ?? "");
  const [comment, setComment] = useState(szi?.comment ?? "");
  const [picked, setPicked] = useState<string[]>(szi?.measure_ids ?? []);
  const [filter, setFilter] = useState("");
  const [found, setFound] = useState<Cert | null | "none">(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const lookup = async () => {
    const n = cert.trim();
    if (!n) return;
    try {
      const c = await apiGet<Cert>(`/szi-registry/${encodeURIComponent(n.replace(/^№\s*/, ""))}`);
      setFound(c);
      if (!name.trim()) setName(c.name);
      if (!trust && c.trust_level) setTrust(String(c.trust_level));
    } catch {
      setFound("none");
    }
  };

  const shown = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return measures.filter(
      (m) => !q || m.measure_id.toLowerCase().includes(q) || m.title.toLowerCase().includes(q),
    );
  }, [measures, filter]);
  // Привязанные меры, которых больше нет в наборе, остаются видны, пока их не снимут.
  const orphan = picked.filter((id) => !measures.some((m) => m.measure_id === id));

  const toggle = (id: string) =>
    setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const body = {
      name: name.trim(),
      kind,
      vendor: vendor.trim() || null,
      version: version.trim() || null,
      cert_number: cert.trim() || null,
      cert_valid_to: validTo || null,
      trust_level: trust ? Number(trust) : null,
      protection_class: cls.trim() || null,
      placement: placement.trim() || null,
      comment: comment.trim() || null,
      measure_ids: picked,
    };
    try {
      if (szi) await apiSend("PATCH", `/object-szi/${szi.id}`, body);
      else await apiSend("POST", `/objects/${objectId}/szi`, body);
      onSaved();
    } catch (e2) {
      setError(message(e2, "Не удалось сохранить"));
      setBusy(false);
    }
  }

  return (
    <Modal
      title={szi ? "Изменить СЗИ" : "Добавить СЗИ"}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="szi-form" className="btn btn-primary" disabled={busy || !name.trim()}>
            Сохранить
          </button>
        </>
      }
    >
      <form id="szi-form" className="form-stack" onSubmit={submit}>
        <div className="form-row">
          <label className="field">
            <span>Номер сертификата ФСТЭК</span>
            <div className="input-row">
              <input
                className="input mono"
                value={cert}
                maxLength={40}
                placeholder="например, 4512"
                onChange={(e) => {
                  setCert(e.target.value);
                  setFound(null);
                }}
                onBlur={() => void lookup()}
              />
              <button type="button" className="btn btn-sm" onClick={() => void lookup()} disabled={!cert.trim()}>
                <Search size={15} /> В реестре
              </button>
            </div>
            <small>Пусто — несертифицированное средство.</small>
          </label>
          <label className="field">
            <span>Вид</span>
            <select className="select" value={kind} onChange={(e) => setKind(e.target.value)}>
              {Object.entries(kinds).map(([k, label]) => (
                <option key={k} value={k}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        </div>
        {found && found !== "none" && (
          <div className="alert alert-ok">
            <ShieldCheck size={15} />
            <span className="alert-text">
              В реестре: <b>{found.name}</b>, действует до {formatDate(found.valid_to)}
              {found.trust_level ? `, УД ${found.trust_level}` : ""}
              {found.withdrawn_at ? " — исключён из реестра" : ""}. Срок и уровень доверия берутся из реестра.
            </span>
          </div>
        )}
        {found === "none" && (
          <div className="alert alert-warn">
            <span className="alert-text">
              Номера нет в загруженном реестре. Проверьте номер или укажите срок действия вручную.
            </span>
          </div>
        )}
        <label className="field">
          <span>Наименование</span>
          <input className="input" value={name} maxLength={300} required onChange={(e) => setName(e.target.value)} />
        </label>
        <div className="form-row">
          <label className="field">
            <span>Производитель</span>
            <input className="input" value={vendor} maxLength={300} onChange={(e) => setVendor(e.target.value)} />
          </label>
          <label className="field">
            <span>Версия</span>
            <input className="input" value={version} maxLength={100} onChange={(e) => setVersion(e.target.value)} />
          </label>
          <label className="field">
            <span>Срок действия сертификата</span>
            <input className="input" type="date" value={validTo} onChange={(e) => setValidTo(e.target.value)} />
            <small>Если номер есть в реестре, действует срок из реестра.</small>
          </label>
          <label className="field">
            <span>Уровень доверия</span>
            <select className="select" value={trust} onChange={(e) => setTrust(e.target.value)}>
              <option value="">не указан</option>
              {[1, 2, 3, 4, 5, 6].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label className="field">
          <span>Класс защиты, профиль</span>
          <input
            className="input"
            value={cls}
            maxLength={200}
            placeholder="например, МЭ типа А 4 класса"
            onChange={(e) => setCls(e.target.value)}
          />
        </label>
        <label className="field">
          <span>Где установлено</span>
          <input
            className="input"
            value={placement}
            maxLength={2000}
            placeholder="хосты, сегменты, число лицензий"
            onChange={(e) => setPlacement(e.target.value)}
          />
        </label>
        <fieldset className="field">
          <span>
            Закрывает меры <span className="muted">· выбрано {picked.length}</span>
          </span>
          {measures.length === 0 ? (
            <small>Набор мер объекта ещё не собран — меры можно будет привязать после него.</small>
          ) : (
            <>
              <input
                className="input"
                type="search"
                placeholder="Код или название меры"
                aria-label="Найти меру"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
              <div className="pick-list" role="group" aria-label="Меры набора">
                {orphan.map((id) => (
                  <label key={id} className="pick-item picked">
                    <input type="checkbox" checked onChange={() => toggle(id)} />
                    <span className="tag tag-muted">{id}</span> <span className="muted">нет в наборе</span>
                  </label>
                ))}
                {shown.map((m) => (
                  <label key={m.id} className={`pick-item${picked.includes(m.measure_id) ? " picked" : ""}`}>
                    <input
                      type="checkbox"
                      checked={picked.includes(m.measure_id)}
                      onChange={() => toggle(m.measure_id)}
                    />
                    <span className="tag">{m.measure_id}</span> {m.title}
                  </label>
                ))}
              </div>
            </>
          )}
        </fieldset>
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
        {error && <ErrorAlert message={error} />}
      </form>
    </Modal>
  );
}

/** Раздел шторки меры: СЗИ, которые закрывают меру, и состояние их сертификатов. */
export function MeasureSziSection({ objectId, measureId }: { objectId: string; measureId: string }) {
  const [data, setData] = useState<SziList | null>(null);
  useEffect(() => {
    let alive = true;
    apiGet<SziList>(`/objects/${objectId}/szi?measure_id=${encodeURIComponent(measureId)}`)
      .then((d) => alive && setData(d))
      .catch(() => alive && setData(null));
    return () => {
      alive = false;
    };
  }, [objectId, measureId]);
  if (!data || data.items.length === 0) return null;
  return (
    <div className="drawer-section">
      <h3>СЗИ</h3>
      {data.counts.bad > 0 && (
        <div className="alert alert-danger">
          <AlertTriangle size={15} />
          <span className="alert-text">
            Сертификат СЗИ недействителен — статус «Реализована» по этой мере нужно перепроверить.
          </span>
        </div>
      )}
      <ul className="plain-list szi-list">
        {data.items.map((s) => (
          <li key={s.id}>
            <div>
              <b>{s.name}</b>
              <div className="cell-sub">
                {s.kind_title}
                {s.cert_number ? ` · № ${s.cert_number}` : ""}
                {s.valid_to ? ` · до ${formatDate(s.valid_to)}` : ""}
              </div>
            </div>
            <StatePill s={s} />
          </li>
        ))}
      </ul>
    </div>
  );
}
