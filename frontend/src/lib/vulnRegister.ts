/** Реестр уязвимостей объекта: оценка критичности по Методике 2025 (задача 2.8). */
import type { Inputs, MethodologyBrief, Outcome, Source } from "./vulnCriticality";

export type VulnState = "current" | "stale" | "not_assessed" | "incomplete" | "not_detected";

export interface Missing {
  indicator: string;
  text: string;
  addresses: string[];
}

export interface AssessmentBrief {
  id: string;
  number: number;
  v: string;
  level: string;
  level_title: string;
  assessed_at: string;
  assessed_by_name: string | null;
  deadline_at: string;
  deadline_from: number;
  overdue: boolean;
  trigger: string;
  trigger_title: string;
}

export interface TraceRowBasis {
  indicator: string;
  group?: string;
  title: string;
  weight?: string;
  chosen?: { code: string; title: string; score: string }[];
  value?: string;
  value_title?: string;
  score: string;
  product?: string;
  rule?: string | null;
  source?: Source;
  basis?: string | null;
  basis_kind?: "bdu" | "inventory" | "specialist" | "scanner";
  fallback?: boolean;
}

export type AssessedOutcome = Omit<Outcome, "trace"> & { trace: TraceRowBasis[] };

export interface CvssInfo {
  target_version: string;
  options: { version: string | null; score: string; vector: string | null; source: string; title: string }[];
  choice: CvssChoice | null;
  score: string | null;
  version: string | null;
  source: string | null;
  fallback: boolean;
  basis: string | null;
}

export interface CvssChoice {
  version: string;
  score: string | number;
  source: string;
  vector?: string | null;
  note?: string | null;
}

export interface Assessment extends AssessmentBrief {
  reasons: string[];
  hosts: string[];
  inputs: Inputs;
  outcome: AssessedOutcome;
  details: { cvss?: Partial<CvssInfo>; notes?: string[] };
  methodology_id: string;
  methodology_version: string;
  methodology_revision: number;
  snapshot_number: number | null;
}

export interface VulnRow {
  id: string;
  bdu_id: string | null;
  title: string;
  origin: "scanner" | "manual";
  manual_source: string | null;
  manual_source_title: string | null;
  cve_ids: string[];
  hosts: string[];
  scanner_hosts: string[];
  manual_hosts: string[];
  last_seen_snapshot: number | null;
  bdu_known: boolean;
  state: VulnState;
  state_title: string;
  missing: Missing[];
  stale_reasons: string[];
  preview: { v: string; level: string; level_title: string } | null;
  current: AssessmentBrief | null;
  assessments: number;
  updated_at: string;
}

export interface Register {
  methodology: { id: string; version: string; revision: number; verified: boolean };
  snapshot: { id: string; number: number; imported_at: string; findings_loaded: boolean } | null;
  counts: Record<"total" | VulnState | "critical" | "high" | "medium" | "low" | "overdue", number>;
  items: VulnRow[];
}

export interface Finding {
  dedup_key: string;
  host: string;
  port: number | null;
  title: string;
  severity: string;
  cvss: number | null;
  cve_ids: string[];
  software?: string | null;
  software_version?: string | null;
}

export interface VulnDetail extends VulnRow {
  description: string | null;
  comment: string | null;
  choices: { cvss: CvssChoice | null; e: string[]; h: string[]; certified_szi: boolean };
  findings: Finding[];
  bdu: {
    bdu_id: string;
    title: string;
    severity: string | null;
    cvss3_score: number | null;
    cvss3_version: string | null;
    cvss3_vector: string | null;
    exploit_raw: string | null;
    in_wild_raw: string | null;
    status: string | null;
    fix_info: string | null;
    withdrawn: boolean;
    criticality_changed_at: string | null;
  } | null;
  proposal: {
    inputs: Inputs;
    hosts: string[];
    missing: Missing[];
    complete: boolean;
    cvss: CvssInfo;
    exploitation: { indicator: string; bdu: string | null; chosen: string[]; values: string[] };
    outcome: AssessedOutcome | null;
    notes: string[];
  };
  history: Assessment[];
  created_at: string;
  created_by_name: string | null;
  updated_by_name: string | null;
}

export const STATE_PILL: Record<VulnState, string> = {
  current: "pill-ok",
  stale: "pill-warn",
  not_assessed: "pill-info",
  incomplete: "pill-warn",
  not_detected: "",
};

export const MANUAL_SOURCES: Record<string, string> = {
  pentest: "Тестирование на проникновение",
  exercise: "Учения (тренировки)",
  experiment: "Эксперимент по повышению защищённости (ПП № 372)",
  other: "Иной контроль защищённости",
};

export const CVSS_VERSIONS = ["3.1", "3.0", "4.0", "2.0"];

export const CVSS_SOURCES: Record<string, string> = {
  bdu: "БДУ ФСТЭК России",
  scanner: "«Сканер»",
  vendor: "Сведения разработчика",
  other_db: "Иная база уязвимостей",
  manual: "Расчёт специалиста",
};

export const BASIS: Record<string, string> = {
  bdu: "БДУ",
  inventory: "Инвентаризация",
  specialist: "Специалист",
  scanner: "«Сканер»",
};

/** Адреса из текста: через пробел, запятую или с новой строки. */
export function parseAddresses(text: string): string[] {
  return [...new Set(text.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean))];
}

export type { MethodologyBrief };
