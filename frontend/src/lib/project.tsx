import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { apiPage, query } from "./api";
import { useAuth } from "./auth";

export interface Member {
  id: string;
  display_name: string;
  roles: string[];
}

export interface Project {
  id: string;
  customer_id: string;
  client: string;
  name: string;
  contract_ref: string | null;
  period_from: string | null;
  period_to: string | null;
  status: "active" | "archived";
  scanner_engagement_id: number | null;
  vm_project_id?: string | null;
  platform_project_id: string | null;
  created_at: string;
  members: Member[];
}

// Текущий проект — общий для продуктов платформы: localStorage platform.project
// и ?project=<uuid> в адресе (контракт платформы v1, п. 3).
export const PROJECT_KEY = "platform.project";

function stored(): string | null {
  try {
    return localStorage.getItem(PROJECT_KEY);
  } catch {
    return null;
  }
}

function store(id: string | null): void {
  try {
    if (id) localStorage.setItem(PROJECT_KEY, id);
    else localStorage.removeItem(PROJECT_KEY);
  } catch {
    // не критично
  }
}

interface ProjectState {
  projects: Project[];
  current: Project | null;
  select: (id: string) => void;
  reload: () => void;
}

const ProjectContext = createContext<ProjectState | null>(null);

export function ProjectProvider({ children }: { children: ReactNode }) {
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const [projects, setProjects] = useState<Project[]>([]);
  const [currentId, setCurrentId] = useState<string | null>(() => params.get("project") ?? stored());
  const allowed = can("view");

  const reload = useCallback(() => {
    if (!allowed) return;
    apiPage<Project>(`/projects${query({ status: "active", limit: 200 })}`)
      .then((p) => setProjects(p.items))
      .catch(() => setProjects([]));
  }, [allowed]);

  useEffect(reload, [reload]);

  // Ссылка с ?project= из другого продукта важнее сохранённого выбора.
  const fromUrl = params.get("project");
  useEffect(() => {
    if (fromUrl) {
      setCurrentId(fromUrl);
      store(fromUrl);
    }
  }, [fromUrl]);

  const current = projects.find((p) => p.id === currentId) ?? projects[0] ?? null;

  const select = useCallback(
    (id: string) => {
      setCurrentId(id);
      store(id);
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          next.set("project", id);
          return next;
        },
        { replace: true },
      );
    },
    [setParams],
  );

  return (
    <ProjectContext.Provider value={{ projects, current, select, reload }}>
      {children}
    </ProjectContext.Provider>
  );
}

export function useProject(): ProjectState {
  const ctx = useContext(ProjectContext);
  if (!ctx) throw new Error("useProject вне ProjectProvider");
  return ctx;
}

export function formatPeriod(p: Pick<Project, "period_from" | "period_to">): string {
  const f = (d: string | null) => (d ? d.split("-").reverse().join(".") : "…");
  if (!p.period_from && !p.period_to) return "—";
  return `${f(p.period_from)} — ${f(p.period_to)}`;
}
