import { AlertTriangle, FolderOpen, Layers } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { EmptyState } from "../components/EmptyState";
import { ImplBar } from "../components/ImplBar";
import { ErrorAlert, Loading } from "../components/Status";
import { apiGet } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDateTime, formatNumber } from "../lib/format";
import { formatPercent, type StatsBucket } from "../lib/measures";
import { KIND_LABELS } from "../lib/objects";
import { useProject } from "../lib/project";
import { STATE_NOTES, type ObjectSummary, type ProjectSummary } from "../lib/summary";

function plural(n: number, one: string, few: string, many: string): string {
  const d = n % 10;
  const h = n % 100;
  if (d === 1 && h !== 11) return one;
  if (d >= 2 && d <= 4 && (h < 12 || h > 14)) return few;
  return many;
}

function regimeList(regimes: string[]): string {
  return regimes.map((r) => `№${r}`).join(", ");
}

export function SummaryPage() {
  const { can } = useAuth();
  const { current } = useProject();
  const [apiDown, setApiDown] = useState(false);
  const [data, setData] = useState<ProjectSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const projectId = can("view") ? current?.id : undefined;

  const load = useCallback(() => {
    if (!projectId) return;
    let alive = true;
    setData(null);
    setError(null);
    apiGet<ProjectSummary>(`/projects/${projectId}/summary`)
      .then((d) => alive && setData(d))
      .catch((e: Error) => alive && setError(e.message));
    return () => {
      alive = false;
    };
  }, [projectId]);

  useEffect(load, [load]);

  useEffect(() => {
    let alive = true;
    apiGet<{ status: string }>("/health/ready")
      .then((r) => alive && setApiDown(r.status !== "ok"))
      .catch(() => alive && setApiDown(true));
    return () => {
      alive = false;
    };
  }, []);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">{current ? `${current.client} · ${current.name}` : "Аттестация"}</div>
          <h1>Сводка</h1>
        </div>
        {projectId && (
          <div className="actions">
            <Link className="btn" to="/objects">
              Все объекты
            </Link>
          </div>
        )}
      </div>

      {apiDown && (
        <div className="alert alert-danger" role="alert">
          <AlertTriangle size={15} />
          Сервер «Аттестации» недоступен. Проверьте, что сервис app запущен.
        </div>
      )}

      {!can("view") ? (
        <section className="card">
          <EmptyState
            icon={<Layers size={21} />}
            title="Сводка для рабочих ролей"
            text="Администратор управляет пользователями и справочниками; объекты проектов ему не видны."
          />
        </section>
      ) : !current ? (
        <section className="card">
          <EmptyState
            icon={<FolderOpen size={21} />}
            title="Нет проектов"
            text="Начните с проекта — договора с заказчиком."
            action={
              <Link className="btn btn-primary" to="/projects">
                К проектам
              </Link>
            }
          />
        </section>
      ) : error ? (
        <ErrorAlert message={error} onRetry={load} />
      ) : data === null ? (
        <Loading />
      ) : (
        <SummaryBody data={data} />
      )}
    </>
  );
}

function SummaryBody({ data }: { data: ProjectSummary }) {
  const k = data.kpi;
  const total = k.stats?.total;
  return (
    <>
      {(k.unverified > 0 || k.unverified_tables.length > 0) && (
        <div className="alert alert-warn" role="status">
          <AlertTriangle size={15} />
          <span className="alert-text">
            <strong>Требует сверки.</strong>{" "}
            {k.unverified_tables.length > 0 &&
              `Таблицы классификации ${regimeList(k.unverified_tables)} не сверены методистом. `}
            {k.unverified > 0 &&
              `${formatNumber(k.unverified)} ${plural(k.unverified, "мера", "меры", "мер")} в наборах объектов — с несверенным сопоставлением. `}
            Результаты оценки предварительные.
          </span>
        </div>
      )}

      <div className="kpi-row summary-kpis">
        <div className="card kpi summary-kpi-main">
          <span className="kpi-label">Реализация мер по проекту</span>
          <span className="kpi-value">{formatPercent(total?.percent)}</span>
          <ImplBar bucket={total} />
          <span className="kpi-delta">
            {k.stats
              ? `авто ${formatPercent(k.stats.auto.percent)} · вручную ${formatPercent(k.stats.manual.percent)}`
              : "наборы мер ещё не сформированы"}
          </span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">Объекты</span>
          <span className="kpi-value">{formatNumber(k.objects)}</span>
          <span className="kpi-delta">
            {formatNumber(k.hosts)} {plural(k.hosts, "хост", "хоста", "хостов")} · в проценте{" "}
            {formatNumber(k.objects_assessed)}
          </span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">Несоответствия</span>
          <span className={`kpi-value${k.nonconformities ? " warn" : ""}`}>
            {formatNumber(k.nonconformities)}
          </span>
          <span className="kpi-delta">не реализованы или частично</span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">Ждут ручной оценки</span>
          <span className={`kpi-value${k.manual_pending ? "" : " muted"}`}>
            {formatNumber(k.manual_pending)}
          </span>
          <span className="kpi-delta">организационные меры</span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">Ждут подтверждения</span>
          <span className={`kpi-value${k.to_confirm ? "" : " muted"}`}>{formatNumber(k.to_confirm)}</span>
          <span className="kpi-delta">подтверждено {formatNumber(k.confirmed)}</span>
        </div>
        <div className="card kpi">
          <span className="kpi-label">Сертификаты СЗИ</span>
          <span className={`kpi-value${k.szi.bad ? " danger" : k.szi.expiring ? " warn" : " muted"}`}>
            {formatNumber(k.szi.bad + k.szi.expiring)}
          </span>
          <span className="kpi-delta">
            {k.szi.total === 0
              ? "СЗИ не заведены"
              : `недействительны ${formatNumber(k.szi.bad)} · истекают за ${k.szi_expiry_days} дн. ${formatNumber(k.szi.expiring)}`}
          </span>
        </div>
      </div>

      <section className="card">
        <div className="card-head">
          <h2>Объекты проекта</h2>
          <span className="muted small">
            «Частично» весит {String(data.partial_weight).replace(".", ",")} в проценте
          </span>
        </div>
        {data.objects.length === 0 ? (
          <EmptyState
            icon={<Layers size={21} />}
            title="Объектов пока нет"
            text="Заведите информационные системы проекта: ГИС, ИСПДн, объекты КИИ."
            action={
              <Link className="btn btn-primary" to="/objects">
                К объектам
              </Link>
            }
          />
        ) : (
          <ObjectsTable rows={data.objects} />
        )}
      </section>
    </>
  );
}

function PercentCell({ bucket }: { bucket: StatsBucket | undefined }) {
  if (!bucket || bucket.total === 0) return <span className="muted">—</span>;
  return (
    <div className="summary-pct">
      <span>{formatPercent(bucket.percent)}</span>
      <ImplBar bucket={bucket} small />
    </div>
  );
}

function SziCell({ o }: { o: ObjectSummary }) {
  const s = o.szi;
  if (s.total === 0) return <span className="muted">—</span>;
  return (
    <Link to={`/objects/${o.id}?tab=szi`} onClick={(e) => e.stopPropagation()} className="pill-stack">
      {s.bad > 0 && <span className="pill pill-danger">недействительны: {formatNumber(s.bad)}</span>}
      {s.expiring > 0 && <span className="pill pill-warn">истекают: {formatNumber(s.expiring)}</span>}
      {s.check > 0 && <span className="pill pill-muted">проверить: {formatNumber(s.check)}</span>}
      {s.bad + s.expiring + s.check === 0 && (
        <span className="pill pill-ok">действуют: {formatNumber(s.total - s.uncertified)}</span>
      )}
    </Link>
  );
}

function ObjectsTable({ rows }: { rows: ObjectSummary[] }) {
  const navigate = useNavigate();
  return (
    <div className="table-wrap">
      <table className="table summary-table">
        <thead>
          <tr>
            <th>Объект</th>
            <th>Класс</th>
            <th>Авто</th>
            <th>Вручную</th>
            <th>Всего</th>
            <th className="num">Несоотв.</th>
            <th>Ждут</th>
            <th>СЗИ</th>
            <th>Снимок «Сканера»</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((o) => {
            const to = `/objects/${o.id}${o.state === "built" ? "?tab=measures" : ""}`;
            return (
              <tr key={o.id} className="clickable" onClick={() => navigate(to)}>
                <td>
                  <Link to={to} className="cell-title" onClick={(e) => e.stopPropagation()}>
                    {o.name}
                  </Link>
                  <div className="cell-sub">
                    {KIND_LABELS[o.kind]}
                    {o.regime ? ` · №${o.regime}` : ""} · {formatNumber(o.host_count)}{" "}
                    {plural(o.host_count, "хост", "хоста", "хостов")}
                  </div>
                </td>
                <td>
                  {o.classification ? (
                    <div className="summary-class">
                      <span className="tag">{o.classification.short}</span>
                      {o.classification.status === "draft" && (
                        <span className="pill pill-muted">Черновик</span>
                      )}
                      {o.class_unverified && (
                        <span className="pill pill-warn" title="Таблица классификации не сверена методистом">
                          Требует сверки
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
                {o.stats ? (
                  <>
                    <td>
                      <PercentCell bucket={o.stats.auto} />
                    </td>
                    <td>
                      <PercentCell bucket={o.stats.manual} />
                    </td>
                    <td>
                      <PercentCell bucket={o.stats.total} />
                    </td>
                    <td className="num">{formatNumber(o.nonconformities)}</td>
                    <td className="summary-wait">
                      {o.manual_pending > 0 && <div>ручной оценки: {formatNumber(o.manual_pending)}</div>}
                      {o.to_confirm > 0 && <div>подтверждения: {formatNumber(o.to_confirm)}</div>}
                      {o.manual_pending === 0 && o.to_confirm === 0 && <span className="muted">—</span>}
                    </td>
                  </>
                ) : (
                  <td colSpan={5} className="muted">
                    {STATE_NOTES[o.state]}
                  </td>
                )}
                <td className="summary-szi">
                  <SziCell o={o} />
                </td>
                <td>
                  {o.snapshot ? (
                    <>
                      <div>
                        №{o.snapshot.number} · прогон №{o.snapshot.run_id}
                      </div>
                      <div className="cell-sub">
                        {formatDateTime(o.snapshot.run_finished_at)}
                        {o.snapshot.coverage_gaps > 0 && " · покрытие неполное"}
                      </div>
                    </>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
