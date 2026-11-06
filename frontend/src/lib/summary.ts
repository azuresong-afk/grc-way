import type { Kind, ObjectBrief } from "./objects";
import type { Stats } from "./measures";
import type { SziCounts } from "./szi";

/** Действие, которое поднимет процент: gain — рост процента по всем мерам, п. п. */
export interface ProgressAction {
  code: "assess_manual" | "assess_auto" | "fix_failed" | "finish_partial";
  count: number;
  gain: number;
  label: string;
}

/**
 * Два процента реализации: по всем мерам (неоценённые = 0, как в «Сводке») и по
 * оценённым (организационные меры без оценки не входят, как на Главной платформы).
 */
export interface Progress {
  percent_all: number | null;
  percent_assessed: number | null;
  total: number;
  assessed_total: number;
  manual_unassessed: number;
  note: string | null;
  actions: ProgressAction[];
}

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
  progress: Progress | null;
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
  szi: SziCounts;
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
    progress: Progress | null;
    nonconformities: number;
    manual_pending: number;
    to_confirm: number;
    confirmed: number;
    unverified: number;
    unverified_tables: string[];
    szi: SziCounts;
    szi_expiry_days: number;
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
