import { useProject } from "../lib/project";

export function ProjectPicker() {
  const { projects, current, select } = useProject();
  if (projects.length === 0) return null;
  return (
    <select
      className="select topbar-project"
      aria-label="Проект"
      value={current?.id ?? ""}
      onChange={(e) => select(e.target.value)}
    >
      {projects.map((p) => (
        <option key={p.id} value={p.id}>
          {p.name} · {p.client}
        </option>
      ))}
    </select>
  );
}
