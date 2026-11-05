import { FolderPlus, FolderOpen } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { Pager } from "../components/Pager";
import { ErrorAlert, Loading } from "../components/Status";
import { apiPage, apiSend, query } from "../lib/api";
import { useAuth } from "../lib/auth";
import { formatPeriod, useProject, type Project } from "../lib/project";
import { PLATFORM } from "../lib/platform";

const LIMIT = 50;

const STATUS_FILTERS: [string, string][] = [
  ["active", "Действующие"],
  ["archived", "В архиве"],
  ["", "Все"],
];

export function ProjectsPage() {
  const { can } = useAuth();
  const { reload: reloadPicker } = useProject();
  const navigate = useNavigate();
  const [items, setItems] = useState<Project[] | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [status, setStatus] = useState("active");
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const load = useCallback(() => {
    setError(null);
    apiPage<Project>(`/projects${query({ status, limit: LIMIT, offset })}`)
      .then((p) => {
        setItems(p.items);
        setTotal(p.total);
      })
      .catch((e: Error) => setError(e.message));
  }, [status, offset]);

  useEffect(load, [load]);

  const manage = can("projects.manage");

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">Аттестация</div>
          <h1>Проекты</h1>
        </div>
        {manage && !PLATFORM && (
          <div className="actions">
            <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
              <FolderPlus size={15} />
              Новый проект
            </button>
          </div>
        )}
      </div>

      {PLATFORM && (
        <p className="muted">
          Проекты, договоры и доступ к ним ведутся в «Платформе»: здесь — проекты, открытые вам.
        </p>
      )}

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

      {error && <ErrorAlert message={error} onRetry={load} />}

      <section className="card">
        {items === null && !error && <Loading />}
        {items?.length === 0 && (
          <EmptyState
            icon={<FolderOpen size={21} />}
            title="Проектов нет"
            text={
              manage
                ? "Проект — это договор с заказчиком. Создайте первый."
                : "Вас пока не добавили ни в один проект."
            }
          />
        )}
        {items && items.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Проект</th>
                  <th>Заказчик</th>
                  <th>Договор</th>
                  <th>Срок</th>
                  <th>Участники</th>
                  <th>Состояние</th>
                </tr>
              </thead>
              <tbody>
                {items.map((p) => (
                  <tr key={p.id} className="clickable" onClick={() => navigate(`/projects/${p.id}`)}>
                    <td>
                      <Link to={`/projects/${p.id}`} className="cell-title">
                        {p.name}
                      </Link>
                    </td>
                    <td>{p.client}</td>
                    <td className="mono">{p.contract_ref ?? "—"}</td>
                    <td className="nowrap">{formatPeriod(p)}</td>
                    <td>{p.members.length}</td>
                    <td>
                      {p.status === "active" ? (
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
        <ProjectDialog
          onClose={() => setCreating(false)}
          onSaved={(p) => {
            setCreating(false);
            reloadPicker();
            navigate(`/projects/${p.id}`);
          }}
        />
      )}
    </>
  );
}

interface Customer {
  id: string;
  name: string;
  inn: string | null;
}

export function ProjectDialog({
  project,
  onClose,
  onSaved,
}: {
  project?: Project;
  onClose: () => void;
  onSaved: (p: Project) => void;
}) {
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [customerId, setCustomerId] = useState(project?.customer_id ?? "");
  const [newCustomer, setNewCustomer] = useState({ name: "", inn: "" });
  const [name, setName] = useState(project?.name ?? "");
  const [contract, setContract] = useState(project?.contract_ref ?? "");
  const [from, setFrom] = useState(project?.period_from ?? "");
  const [to, setTo] = useState(project?.period_to ?? "");
  const [engagement, setEngagement] = useState(project?.scanner_engagement_id?.toString() ?? "");
  const [vmProject, setVmProject] = useState(project?.vm_project_id ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (project) return;
    apiPage<Customer>("/customers?limit=200")
      .then((p) => {
        setCustomers(p.items);
        setCustomerId((cur) => cur || p.items[0]?.id || "new");
      })
      .catch(() => setCustomerId("new"));
  }, [project]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const fields = {
      name,
      contract_ref: contract || null,
      period_from: from || null,
      period_to: to || null,
      scanner_engagement_id: engagement ? Number(engagement) : null,
      vm_project_id: vmProject.trim() || null,
    };
    try {
      if (project) {
        onSaved(await apiSend<Project>("PATCH", `/projects/${project.id}`, fields));
        return;
      }
      let cid = customerId;
      if (cid === "new") {
        const c = await apiSend<Customer>("POST", "/customers", {
          name: newCustomer.name,
          inn: newCustomer.inn || null,
        });
        cid = c.id;
      }
      onSaved(await apiSend<Project>("POST", "/projects", { customer_id: cid, ...fields }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось сохранить");
    } finally {
      setBusy(false);
    }
  }

  const formId = "project-form";
  return (
    <Modal
      title={project ? "Изменить проект" : "Новый проект"}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form={formId} className="btn btn-primary" disabled={busy}>
            {project ? "Сохранить" : "Создать"}
          </button>
        </>
      }
    >
      <form id={formId} className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        {!project && (
          <label className="field">
            <span>Заказчик</span>
            <select
              className="select"
              value={customerId}
              onChange={(e) => setCustomerId(e.target.value)}
            >
              {customers.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                  {c.inn ? ` · ИНН ${c.inn}` : ""}
                </option>
              ))}
              <option value="new">+ Новый заказчик</option>
            </select>
          </label>
        )}
        {!project && customerId === "new" && (
          <div className="form-row">
            <label className="field">
              <span>Наименование заказчика</span>
              <input
                className="input"
                value={newCustomer.name}
                onChange={(e) => setNewCustomer({ ...newCustomer, name: e.target.value })}
                required
              />
            </label>
            <label className="field">
              <span>ИНН</span>
              <input
                className="input mono"
                value={newCustomer.inn}
                onChange={(e) => setNewCustomer({ ...newCustomer, inn: e.target.value.trim() })}
                pattern="\d{10}|\d{12}"
                inputMode="numeric"
              />
            </label>
          </div>
        )}
        <label className="field">
          <span>Название проекта</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} required />
        </label>
        <label className="field">
          <span>Номер договора</span>
          <input className="input" value={contract} onChange={(e) => setContract(e.target.value)} />
        </label>
        <div className="form-row">
          <label className="field">
            <span>Начало работ</span>
            <input className="input" type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
          </label>
          <label className="field">
            <span>Окончание</span>
            <input className="input" type="date" value={to} onChange={(e) => setTo(e.target.value)} />
          </label>
        </div>
        <label className="field">
          <span>Проект в «Сканере»</span>
          <input
            className="input mono"
            value={engagement}
            onChange={(e) => setEngagement(e.target.value.replace(/\D/g, ""))}
            inputMode="numeric"
          />
          <small>Номер engagement — оттуда придут активы и результаты проверок</small>
        </label>
        <label className="field">
          <span>Проект в «Устранении»</span>
          <input
            className="input mono"
            value={vmProject}
            onChange={(e) => setVmProject(e.target.value.replace(/[^A-Za-z0-9_.:-]/g, ""))}
            maxLength={64}
          />
          <small>Идентификатор проекта — туда уйдут заявки по несоответствиям</small>
        </label>
      </form>
    </Modal>
  );
}
