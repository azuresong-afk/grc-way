import { Archive, ArchiveRestore, Pencil, Users } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { apiGet, apiSend } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatDateTime } from "../lib/format";
import { formatPeriod, useProject, type Member, type Project } from "../lib/project";
import { roleList } from "../lib/roles";
import { ProjectDialog } from "./ProjectsPage";

export function ProjectPage() {
  const { id = "" } = useParams();
  const { me, can } = useAuth();
  const { current, select, reload: reloadPicker } = useProject();
  const [project, setProject] = useState<Project | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [members, setMembers] = useState(false);

  const load = useCallback(() => {
    setError(null);
    apiGet<Project>(`/projects/${id}`)
      .then(setProject)
      .catch((e: Error) => setError(e.message));
  }, [id]);

  useEffect(load, [load]);

  // Открытый действующий проект становится текущим в верхней полосе.
  const openedId = project?.status === "active" ? project.id : null;
  useEffect(() => {
    if (openedId && current?.id !== openedId) select(openedId);
  }, [openedId, current?.id, select]);

  const saved = (p: Project) => {
    setProject(p);
    setEditing(false);
    setMembers(false);
    reloadPicker();
  };

  async function toggleArchive() {
    if (!project) return;
    try {
      saved(
        await apiSend<Project>("PATCH", `/projects/${project.id}`, {
          status: project.status === "active" ? "archived" : "active",
        }),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось изменить проект");
    }
  }

  if (error && !project) return <ErrorAlert message={error} onRetry={load} />;
  if (!project) return <Loading />;
  const manage = can("projects.manage");

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            <Link to="/projects">Проекты</Link> / {project.client}
          </div>
          <h1>{project.name}</h1>
        </div>
        {manage && (
          <div className="actions">
            <button type="button" className="btn" onClick={toggleArchive}>
              {project.status === "active" ? <Archive size={15} /> : <ArchiveRestore size={15} />}
              {project.status === "active" ? "В архив" : "Вернуть из архива"}
            </button>
            <button type="button" className="btn btn-primary" onClick={() => setEditing(true)}>
              <Pencil size={15} />
              Изменить
            </button>
          </div>
        )}
      </div>

      {error && <ErrorAlert message={error} />}

      <div className="row-phi">
        <section className="card">
          <div className="card-head">
            <h2>Договор</h2>
            {project.status === "active" ? (
              <span className="pill pill-ok">Действует</span>
            ) : (
              <span className="pill pill-muted">В архиве</span>
            )}
          </div>
          <dl className="props card-pad">
            <dt>Заказчик</dt>
            <dd>{project.client}</dd>
            <dt>Номер договора</dt>
            <dd className="mono">{project.contract_ref ?? "—"}</dd>
            <dt>Срок работ</dt>
            <dd>{formatPeriod(project)}</dd>
            <dt>Проект в «Сканере»</dt>
            <dd className="mono">{project.scanner_engagement_id ?? "не связан"}</dd>
            <dt>Создан</dt>
            <dd>{formatDateTime(project.created_at)}</dd>
          </dl>
        </section>

        <section className="card">
          <div className="card-head">
            <h2>Участники</h2>
            {manage && (
              <button type="button" className="btn btn-sm" onClick={() => setMembers(true)}>
                <Users size={15} />
                Изменить
              </button>
            )}
          </div>
          <ul className="member-list">
            {project.members.map((m) => (
              <li key={m.id}>
                <span className="cell-title">{m.display_name}</span>
                <span className="cell-sub">{roleList(m.roles)}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      {editing && (
        <ProjectDialog project={project} onClose={() => setEditing(false)} onSaved={saved} />
      )}
      {members && me && (
        <MembersDialog
          project={project}
          selfId={me.id}
          onClose={() => setMembers(false)}
          onSaved={saved}
        />
      )}
    </>
  );
}

function MembersDialog({
  project,
  selfId,
  onClose,
  onSaved,
}: {
  project: Project;
  selfId: string;
  onClose: () => void;
  onSaved: (p: Project) => void;
}) {
  const [directory, setDirectory] = useState<Member[] | null>(null);
  const [chosen, setChosen] = useState(new Set(project.members.map((m) => m.id)));
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<Member[]>("/directory/users")
      .then(setDirectory)
      .catch((e: Error) => setError(e.message));
  }, []);

  async function save() {
    try {
      onSaved(
        await apiSend<Project>("PUT", `/projects/${project.id}/members`, {
          user_ids: [...chosen],
        }),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось сохранить");
    }
  }

  return (
    <Modal
      title="Участники проекта"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" onClick={save}>
            Сохранить
          </button>
        </>
      }
    >
      {error && <ErrorAlert message={error} />}
      {!directory && !error && <Loading />}
      {directory?.map((u) => (
        <label key={u.id} className="check">
          <input
            type="checkbox"
            checked={chosen.has(u.id)}
            disabled={u.id === selfId}
            onChange={() =>
              setChosen((prev) => {
                const next = new Set(prev);
                if (next.has(u.id)) next.delete(u.id);
                else next.add(u.id);
                return next;
              })
            }
          />
          <span>
            <b>{u.display_name}</b>
            <small>{roleList(u.roles)}</small>
          </span>
        </label>
      ))}
    </Modal>
  );
}
