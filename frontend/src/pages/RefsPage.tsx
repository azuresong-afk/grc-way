import {
  BookOpen,
  Bug,
  CheckCheck,
  ExternalLink,
  FileText,
  Gauge,
  GitCompareArrows,
  Pencil,
  ShieldAlert,
  ShieldCheck,
  Table2,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Drawer } from "../components/Drawer";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { VerifyBadge } from "../components/VerifyBadge";
import { apiGet, apiPage, apiSend, query } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDateTime, formatNumber } from "../lib/format";

interface Group {
  code: string;
  title: string;
  total: number;
  unverified: number;
}

interface Profile {
  id: string;
  title: string;
  short: string;
  document: string | null;
  url: string | null;
  level_label: string | null;
  levels: string[];
  dynamic: string | null;
  imported_at: string;
  scanner_synced_at: string | null;
  total: number;
  unverified: number;
  groups: Group[];
}

interface Source {
  document?: string;
  clause?: string | null;
  appendix?: string | null;
  url?: string | null;
  note?: string | null;
}

interface Measure {
  profile_id: string;
  id: string;
  group_code: string;
  title: string;
  text: string | null;
  levels: string[];
  checks: string[];
  kind: "technical" | "organizational";
  source: Source;
  origin: string;
  verified: boolean;
  verified_by_name: string | null;
  verified_at: string | null;
  revision: number;
  updated_at: string;
}

interface MeasureDetail extends Measure {
  check_details: { id: string; title: string; platform: string; remediation: string | null }[];
  revisions: {
    revision: number;
    changed_by_name: string | null;
    changed_at: string;
    comment: string | null;
  }[];
}

const ORIGIN: Record<string, string> = {
  scanner: "Импорт из «Сканера»",
  local: "Изменено в интерфейсе",
  official: "Из официального текста",
  stub: "Заглушка",
};

type Filter = "all" | "unverified" | "organizational" | "technical";
const FILTERS: [Filter, string][] = [
  ["all", "Все"],
  ["unverified", "Требует сверки"],
  ["organizational", "Проверяется вручную"],
  ["technical", "Проверяется «Сканером»"],
];

export function RefsPage() {
  const [params, setParams] = useSearchParams();
  const [profiles, setProfiles] = useState<Profile[] | null>(null);
  const [measures, setMeasures] = useState<Measure[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [opened, setOpened] = useState<Measure | null>(null);

  const profileId = params.get("profile") ?? "fstec-117";
  const group = params.get("group") ?? "";
  const filter = (params.get("filter") as Filter | null) ?? "all";
  const profile = profiles?.find((p) => p.id === profileId) ?? null;

  const set = (patch: Record<string, string>) =>
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

  const loadProfiles = useCallback(() => {
    apiGet<Profile[]>("/refs/profiles")
      .then(setProfiles)
      .catch((e: Error) => setError(e.message));
  }, []);

  const loadMeasures = useCallback(() => {
    setError(null);
    setMeasures(null);
    apiPage<Measure>(
      `/refs/measures${query({
        profile: profileId,
        group,
        limit: 500,
        verified: filter === "unverified" ? "false" : undefined,
        kind: filter === "organizational" || filter === "technical" ? filter : undefined,
      })}`,
    )
      .then((p) => setMeasures(p.items))
      .catch((e: Error) => setError(e.message));
  }, [profileId, group, filter]);

  useEffect(loadProfiles, [loadProfiles]);
  useEffect(loadMeasures, [loadMeasures]);

  const byGroup = useMemo(() => {
    const out = new Map<string, Measure[]>();
    for (const m of measures ?? []) out.set(m.group_code, [...(out.get(m.group_code) ?? []), m]);
    return out;
  }, [measures]);

  const changed = (m: Measure) => {
    setMeasures((list) => list?.map((x) => (x.id === m.id ? m : x)) ?? null);
    loadProfiles();
  };

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">Справочники</div>
          <h1>Профили мер</h1>
        </div>
        <div className="actions">
          <Link to="/refs/classification" className="btn">
            <Table2 size={15} /> Таблицы классификации
          </Link>
          <Link to="/refs/threats" className="btn">
            <ShieldAlert size={15} /> Методика оценки угроз
          </Link>
          <Link to="/refs/bdu" className="btn">
            <Bug size={15} /> БДУ ФСТЭК
          </Link>
          <Link to="/refs/szi" className="btn">
            <ShieldCheck size={15} /> Реестр СЗИ
          </Link>
          <Link to="/refs/vuln-criticality" className="btn">
            <Gauge size={15} /> Критичность уязвимостей
          </Link>
          <Link to="/refs/documents" className="btn">
            <FileText size={15} /> Нормативные документы
          </Link>
          <Link to="/refs/scanner" className="btn">
            <GitCompareArrows size={15} /> Обновление из «Сканера»
          </Link>
        </div>
      </div>

      {profiles && (
        <div className="tabs" role="tablist" aria-label="Нормативный документ">
          {profiles.map((p) => (
            <button
              key={p.id}
              type="button"
              role="tab"
              className="tab"
              aria-selected={p.id === profileId}
              onClick={() => set({ profile: p.id, group: "" })}
            >
              {p.short}
              {p.unverified > 0 && <span className="count">{formatNumber(p.unverified)}</span>}
            </button>
          ))}
        </div>
      )}

      {profile && (
        <div className="alert alert-warn">
          <span className="alert-text">
            {profile.document ?? profile.title}
            {profile.url && (
              <>
                {" "}
                <a href={profile.url} target="_blank" rel="noreferrer noopener">
                  Текст документа <ExternalLink size={12} />
                </a>
              </>
            )}
            <br />
            Меры импортированы из «Сканера» {formatDateTime(profile.scanner_synced_at ?? profile.imported_at)}. Не сверено
            методистом: {formatNumber(profile.unverified)} из {formatNumber(profile.total)}.
          </span>
        </div>
      )}

      {profile?.dynamic && (
        <EmptyState
          icon={<BookOpen size={21} />}
          title="Динамический профиль"
          text="Пункты этого профиля берутся из результатов прогона «Сканера», справочника мер у него нет."
        />
      )}

      {profile && !profile.dynamic && (
        <div className="toolbar">
          <select
            className="select toolbar-select"
            aria-label="Группа мер"
            value={group}
            onChange={(e) => set({ group: e.target.value })}
          >
            <option value="">Все группы</option>
            {profile.groups.map((g) => (
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
                onClick={() => set({ filter: value === "all" ? "" : value })}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      )}

      {error && <ErrorAlert message={error} onRetry={loadMeasures} />}
      {!profile?.dynamic && measures === null && !error && <Loading />}

      {profile && !profile.dynamic && measures?.length === 0 && (
        <section className="card">
          <EmptyState
            icon={<CheckCheck size={21} />}
            title="Ничего не найдено"
            text="Под выбранные фильтры мер нет."
          />
        </section>
      )}

      {profile &&
        measures &&
        profile.groups
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
                <table className="table">
                  <thead>
                    <tr>
                      <th>Мера</th>
                      <th>Наименование</th>
                      <th>{profile.level_label ?? "Уровни"}</th>
                      <th>Оценка</th>
                      <th>Сверка</th>
                    </tr>
                  </thead>
                  <tbody>
                    {byGroup.get(g.code)?.map((m) => (
                      <tr
                        key={m.id}
                        className={`clickable${opened?.id === m.id ? " selected" : ""}`}
                        onClick={() => setOpened(m)}
                      >
                        <td className="nowrap">
                          <button type="button" className="link-btn" onClick={() => setOpened(m)}>
                            <span className="tag">{m.id}</span>
                          </button>
                        </td>
                        <td>{m.title}</td>
                        <td className="nowrap">
                          {m.levels.length ? m.levels.join(", ") : <span className="muted">вне базового набора</span>}
                        </td>
                        <td className="nowrap">
                          {m.kind === "technical" ? (
                            <span className="pill pill-info">«Сканер»</span>
                          ) : (
                            <span className="pill pill-muted">Вручную</span>
                          )}
                        </td>
                        <td>
                          <VerifyBadge verified={m.verified} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ))}

      {opened && profile && (
        <MeasureDrawer
          key={`${opened.id}-${opened.revision}`}
          measure={opened}
          profile={profile}
          onClose={() => setOpened(null)}
          onChanged={(m) => {
            setOpened(m);
            changed(m);
          }}
        />
      )}
    </>
  );
}

function MeasureDrawer({
  measure,
  profile,
  onClose,
  onChanged,
}: {
  measure: Measure;
  profile: Profile;
  onClose: () => void;
  onChanged: (m: Measure) => void;
}) {
  const { can } = useAuth();
  const [detail, setDetail] = useState<MeasureDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);

  useEffect(() => {
    apiGet<MeasureDetail>(
      `/refs/measures/${encodeURIComponent(measure.profile_id)}/${encodeURIComponent(measure.id)}`,
    )
      .then(setDetail)
      .catch((e: Error) => setError(e.message));
  }, [measure.profile_id, measure.id, measure.revision]);

  async function verify() {
    try {
      onChanged(
        await apiSend<Measure>(
          "POST",
          `/refs/measures/${encodeURIComponent(measure.profile_id)}/${encodeURIComponent(measure.id)}/verify`,
          { revision: measure.revision },
        ),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось отметить сверку");
    }
  }

  const src = measure.source;
  return (
    <Drawer
      title={
        <>
          <span className="tag">{measure.id}</span> {measure.title}
        </>
      }
      subtitle={`${profile.short} · ${measure.group_code} · ревизия ${measure.revision}`}
      onClose={onClose}
      footer={
        <>
          {can("refs.manage") && (
            <button type="button" className="btn" onClick={() => setEditing(true)}>
              <Pencil size={15} />
              Изменить
            </button>
          )}
          {can("refs.verify") && !measure.verified && (
            <button type="button" className="btn btn-primary" onClick={verify}>
              <CheckCheck size={15} />
              Сверено
            </button>
          )}
        </>
      }
    >
      {error && <ErrorAlert message={error} />}
      <div className="drawer-section">
        <VerifyBadge verified={measure.verified} />
        {measure.verified ? (
          <p className="muted">
            Сверил(а) {measure.verified_by_name}, {formatDateTime(measure.verified_at)}
          </p>
        ) : (
          <p className="muted">
            Пока запись не сверена, она отмечается в интерфейсе, а документы с ней получают
            водяной знак «Проект».
          </p>
        )}
      </div>

      <div className="drawer-section">
        <h3>Требование</h3>
        {measure.text ? (
          <p className="prewrap">{measure.text}</p>
        ) : (
          <div className="alert alert-info">
            <span className="alert-text">
              Текст требования не загружен — показано только наименование меры.
            </span>
          </div>
        )}
        <dl className="props">
          <dt>{profile.level_label ?? "Уровни"}</dt>
          <dd>{measure.levels.length ? measure.levels.join(", ") : "вне базового набора"}</dd>
          <dt>Источник</dt>
          <dd>
            {src.document ?? "—"}
            {src.appendix && `, приложение ${src.appendix}`}
            {src.clause && `, п. ${src.clause}`}
            {src.note && <div className="cell-sub">{src.note}</div>}
          </dd>
          <dt>Происхождение</dt>
          <dd>{ORIGIN[measure.origin] ?? measure.origin}</dd>
        </dl>
      </div>

      <div className="drawer-section">
        <h3>Проверки «Сканера»</h3>
        {measure.checks.length === 0 && (
          <p className="muted">
            Организационная мера: проверяется вручную (документ, интервью, осмотр) и в
            автоматический процент не входит.
          </p>
        )}
        {detail?.check_details.map((c) => (
          <div key={c.id} className="check-item">
            <div>
              <span className="tag">{c.id}</span> {c.title}
              <span className="cell-sub"> · {c.platform}</span>
            </div>
            {c.remediation && <div className="cell-sub">{c.remediation}</div>}
          </div>
        ))}
        {measure.checks.length > 0 && (
          <p className="cell-sub">
            Сопоставление меры с проверками сделано разработчиком «Сканера» и требует сверки.
          </p>
        )}
      </div>

      {detail && detail.revisions.length > 0 && (
        <div className="drawer-section">
          <h3>История правок</h3>
          <ul className="history">
            {detail.revisions.map((r) => (
              <li key={r.revision}>
                <span>
                  Ревизия {r.revision} → {r.revision + 1}: {r.changed_by_name ?? "—"},{" "}
                  {formatDateTime(r.changed_at)}
                </span>
                {r.comment && <span className="cell-sub">{r.comment}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}

      {editing && (
        <MeasureEditDialog
          measure={measure}
          profile={profile}
          onClose={() => setEditing(false)}
          onSaved={(m) => {
            setEditing(false);
            onChanged(m);
          }}
        />
      )}
    </Drawer>
  );
}

function MeasureEditDialog({
  measure,
  profile,
  onClose,
  onSaved,
}: {
  measure: Measure;
  profile: Profile;
  onClose: () => void;
  onSaved: (m: Measure) => void;
}) {
  const [title, setTitle] = useState(measure.title);
  const [text, setText] = useState(measure.text ?? "");
  const [levels, setLevels] = useState(new Set(measure.levels));
  const [document, setDocument] = useState(measure.source.document ?? "");
  const [appendix, setAppendix] = useState(measure.source.appendix ?? "");
  const [clause, setClause] = useState(measure.source.clause ?? "");
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      onSaved(
        await apiSend<Measure>(
          "PATCH",
          `/refs/measures/${encodeURIComponent(measure.profile_id)}/${encodeURIComponent(measure.id)}`,
          {
            title,
            text: text || null,
            levels: profile.levels.filter((l) => levels.has(l)),
            source: {
              ...measure.source,
              document,
              appendix: appendix || null,
              clause: clause || null,
            },
            comment,
          },
        ),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось сохранить");
    }
  }

  return (
    <Modal
      title={`Изменить меру ${measure.id}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="measure-form" className="btn btn-primary">
            Сохранить
          </button>
        </>
      }
    >
      <form id="measure-form" className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <div className="alert alert-info">
          <span className="alert-text">
            После сохранения запись снова потребует сверки методистом.
          </span>
        </div>
        <label className="field">
          <span>Наименование</span>
          <input className="input" value={title} onChange={(e) => setTitle(e.target.value)} required />
        </label>
        <label className="field">
          <span>Текст требования</span>
          <textarea className="textarea" value={text} onChange={(e) => setText(e.target.value)} />
          <small>Дословно из официального документа</small>
        </label>
        <fieldset className="field">
          <span>{profile.level_label ?? "Уровни"} (базовый набор)</span>
          <div className="chips">
            {profile.levels.map((l) => (
              <label key={l} className="check check-inline">
                <input
                  type="checkbox"
                  checked={levels.has(l)}
                  onChange={() =>
                    setLevels((prev) => {
                      const next = new Set(prev);
                      if (next.has(l)) next.delete(l);
                      else next.add(l);
                      return next;
                    })
                  }
                />
                <span>{l}</span>
              </label>
            ))}
          </div>
        </fieldset>
        <label className="field">
          <span>Документ-источник</span>
          <input
            className="input"
            value={document}
            onChange={(e) => setDocument(e.target.value)}
            required
          />
        </label>
        <div className="form-row">
          <label className="field">
            <span>Приложение</span>
            <input className="input" value={appendix} onChange={(e) => setAppendix(e.target.value)} />
          </label>
          <label className="field">
            <span>Пункт</span>
            <input className="input" value={clause} onChange={(e) => setClause(e.target.value)} />
          </label>
        </div>
        <label className="field">
          <span>Основание правки</span>
          <input
            className="input"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            required
          />
          <small>Попадёт в историю правок и журнал аудита</small>
        </label>
      </form>
    </Modal>
  );
}
