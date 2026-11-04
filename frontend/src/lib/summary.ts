import type { Kind, ObjectBrief } from "./objects";
import type { Stats } from "./measures";

export interface ObjectSummary {
  id: string;
  name: string;
  kind: Kind;
  regime: string | null;
  status: string;
  host_count: number;
  classification: ObjectBrief["classification"];
  class_unverified: boolean;
  state: "no_regime" | "no_class" | "not_built" | "built";
  stats: Stats | null;
  adaptation: { version: number; status: string } | null;
  snapshot: {
    id: string;
    number: number;
    run_id: number;
    run_name: string | null;
    run_finished_at: string | null;
    imported_at: string;
    coverage_gaps: number;
  } | null;
  snapshots: number;
  measures: number;
  nonconformities: number;
  manual_pending: number;
  to_confirm: number;
  confirmed: number;
  unverified: number;
}

export interface ProjectSummary {
  project_id: string;
  name: string;
  client: string;
  partial_weight: number;
  kpi: {
    objects: number;
    hosts: number;
    objects_assessed: number;
    stats: Stats | null;
    nonconformities: number;
    manual_pending: number;
    to_confirm: number;
    confirmed: number;
    unverified: number;
    unverified_tables: string[];
  };
  objects: ObjectSummary[];
}

export type SearchKind = "project" | "object" | "host" | "measure";

export interface SearchItem {
  kind: SearchKind;
  id: string;
  title: string;
  subtitle: string | null;
  project_id: string;
  path: string;
  url: string;
}

export const STATE_NOTES: Record<ObjectSummary["state"], string> = {
  no_regime: "Не выбран режим защиты",
  no_class: "Класс не утверждён",
  not_built: "Набор мер не сформирован",
  built: "",
};
