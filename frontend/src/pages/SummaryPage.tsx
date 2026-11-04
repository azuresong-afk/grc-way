import { AlertTriangle, FolderOpen, Layers } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { EmptyState } from "../components/EmptyState";
import { Loading } from "../components/Status";
import { apiGet, apiPage, query } from "../lib/api";
import { useAuth } from "../lib/auth";
import { KIND_LABELS, type ObjectBrief } from "../lib/objects";
import { useProject } from "../lib/project";

export function SummaryPage() {
  const { can } = useAuth();
  const { current } = useProject();
  const [apiDown, setApiDown] = useState(false);
  const [objects, setObjects] = useState<ObjectBrief[] | null>(null);
  const navigate = useNavigate();
  const projectId = can("view") ? current?.id : undefined;

  useEffect(() => {
    if (!projectId) return;
    let alive = true;
    setObjects(null);
    apiPage<ObjectBrief>(`/projects/${projectId}/objects${query({ status: "active", limit: 200 })}`)
      .then((p) => alive && setObjects(p.items))
      .catch(() => alive && setObjects([]));
    return () => {
      alive = false;
    };
  }, [projectId]);

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
      </div>

      {apiDown && (
        <div className="alert alert-danger" role="alert">
          <AlertTriangle size={15} />
          Сервер «Аттестации» недоступен. Проверьте, что сервис app запущен.
        </div>
      )}

      <section className="card">
        <div className="card-head">
          <h2>Объекты проекта</h2>
          {projectId && (
            <Link className="btn btn-sm" to="/objects">
              Все объекты
            </Link>
          )}
        </div>
        {!can("view") ? (
          <EmptyState
            icon={<Layers size={21} />}
            title="Сводка для рабочих ролей"
            text="Администратор управляет пользователями и справочниками; объекты проектов ему не видны."
          />
        ) : current ? (
          objects === null ? (
            <Loading />
          ) : objects.length === 0 ? (
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
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Объект</th>
                    <th>Вид</th>
                    <th>Режим</th>
                    <th className="num">Хосты</th>
                  </tr>
                </thead>
                <tbody>
                  {objects.map((o) => (
                    <tr key={o.id} className="clickable" onClick={() => navigate(`/objects/${o.id}`)}>
                      <td>
                        <Link to={`/objects/${o.id}`} className="cell-title">
                          {o.name}
                        </Link>
                      </td>
                      <td>
                        <span className="tag">{KIND_LABELS[o.kind]}</span>
                      </td>
                      <td>{o.regime ? `№${o.regime}` : "—"}</td>
                      <td className="num">{o.host_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        ) : (
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
        )}
      </section>
    </>
  );
}
