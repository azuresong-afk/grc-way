import { AlertTriangle, FolderOpen, Layers } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { EmptyState } from "../components/EmptyState";
import { apiGet } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useProject } from "../lib/project";

export function SummaryPage() {
  const { can } = useAuth();
  const { current } = useProject();
  const [apiDown, setApiDown] = useState(false);

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
        </div>
        {!can("view") ? (
          <EmptyState
            icon={<Layers size={21} />}
            title="Сводка для рабочих ролей"
            text="Администратор управляет пользователями и справочниками; объекты проектов ему не видны."
          />
        ) : current ? (
          <EmptyState
            icon={<Layers size={21} />}
            title="Объектов пока нет"
            text="Информационные системы проекта появятся здесь, когда будет готов раздел «Объекты»."
          />
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
