import { AlertTriangle, CheckCircle2, FolderOpen } from "lucide-react";
import { useEffect, useState } from "react";
import { EmptyState } from "../components/EmptyState";
import { apiGet } from "../lib/api";

type ApiState = "loading" | "ok" | "error";

export function SummaryPage() {
  const [api, setApi] = useState<ApiState>("loading");

  useEffect(() => {
    let alive = true;
    apiGet<{ status: string }>("/health/ready")
      .then((r) => alive && setApi(r.status === "ok" ? "ok" : "error"))
      .catch(() => alive && setApi("error"));
    return () => {
      alive = false;
    };
  }, []);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">Аттестация</div>
          <h1>Сводка</h1>
        </div>
      </div>

      {api === "error" && (
        <div className="alert alert-danger" role="alert">
          <AlertTriangle size={15} />
          Сервер «Аттестации» недоступен. Проверьте, что сервис app запущен.
        </div>
      )}
      {api === "ok" && (
        <div className="alert alert-ok">
          <CheckCircle2 size={15} />
          Сервер и база данных доступны.
        </div>
      )}

      <section className="card">
        <div className="card-head">
          <h2>Объекты проекта</h2>
        </div>
        <EmptyState
          icon={<FolderOpen size={21} />}
          title="Объектов пока нет"
          text="Проекты и объекты появятся в следующих задачах плана: сначала вход и роли, затем проекты."
        />
      </section>
    </>
  );
}
