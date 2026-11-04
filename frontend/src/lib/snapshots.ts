// Снимки результатов прогонов «Сканера» и автоматические доказательства мер (задача 1.9).
import type { MeasureStatus } from "./measures";

export type AutoStatus = Exclude<MeasureStatus, "not_applicable">;

export interface ScannerRun {
  id: number;
  name: string | null;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  modules: string[];
  error_message: string | null;
  snapshots: number[];
}

export interface RunsList {
  engagement_id: number;
  source: string;
  mode: "live" | "fixture";
  runs: ScannerRun[];
  latest_id: number | null;
}

export interface SnapshotSummary {
  measures: number;
  implemented: number;
  partial: number;
  not_implemented: number;
  unassessed: number;
  applied: number;
  kept_manual: number;
}

export interface SnapshotBrief {
  id: string;
  number: number;
  current: boolean;
  run_id: number;
  run_name: string | null;
  run_status: string;
  run_started_at: string | null;
  run_finished_at: string | null;
  selection: "latest" | "manual";
  profile_id: string;
  level: string | null;
  adaptation_version: number | null;
  percent: number | null;
  counts: Partial<Record<"passed" | "failed" | "na" | "manual", number>>;
  summary: Partial<SnapshotSummary>;
  hosts: number;
  coverage_gaps: number;
  source: string;
  imported_at: string;
  imported_by_name: string | null;
}

export interface CheckFailure {
  id: string;
  failures: {
    kind?: string;
    title?: string;
    vuln_id?: string;
    severity?: string;
  }[];
  more: number;
}

export interface FailedHost {
  host: string;
  checks: CheckFailure[];
}

export interface Recommendation {
  check: string;
  title: string;
  remediation: string | null;
  doc: string | null;
}

export interface SnapshotControl {
  id: string;
  title: string;
  group: string;
  status: "passed" | "failed" | "na";
  hosts: Record<string, number>;
  failed_hosts: FailedHost[];
  recommendations: Recommendation[];
  measure_status: AutoStatus | null;
  note: string | null;
}

export interface CoverageHost {
  host: string;
  in_object: boolean;
  status: string | null;
  modules: Record<
    string,
    { status: string; label?: string | null; reason?: string | null }
  >;
}

export interface SnapshotFull extends SnapshotBrief {
  controls: SnapshotControl[];
  manual: { id: string; title: string; group: string }[];
  coverage_hosts: CoverageHost[];
  missing_hosts: string[];
}

export interface ImportResult {
  snapshot: SnapshotBrief;
  applied: number;
  kept_manual: number;
}

export interface ScannerEvidenceData {
  status: AutoStatus;
  reason:
    | "passed"
    | "failed_all"
    | "failed_some"
    | "not_checked"
    | "incomplete"
    | "absent";
  note: string;
  control_status: string | null;
  hosts: string[];
  checked: string[];
  failed: string[];
  unchecked: { host: string; reason: string }[];
  not_applicable: string[];
  outside_failed: string[];
  run: {
    id: number;
    name: string | null;
    status: string;
    finished_at: string | null;
    percent: number | null;
  };
  failed_hosts: FailedHost[];
  recommendations: Recommendation[];
  host_counts: Record<string, number>;
}

export interface Evidence {
  id: string;
  kind: "scanner" | "file" | "interview" | "inspection" | "certificate";
  status: AutoStatus | null;
  summary: string;
  data: ScannerEvidenceData;
  snapshot: SnapshotBrief | null;
  created_at: string;
  created_by_name: string | null;
}

export const RUN_STATUS: Record<string, [string, string]> = {
  done: ["Завершён", "pill-ok"],
  partial: ["Частично", "pill-warn"],
  failed: ["Ошибка", "pill-danger"],
  stopped: ["Остановлен", "pill-muted"],
  interrupted: ["Прерван", "pill-muted"],
  running: ["Идёт", "pill-running"],
  pending: ["В очереди", "pill-muted"],
};

export function runStatus(s: string): [string, string] {
  return RUN_STATUS[s] ?? [s, "pill-muted"];
}

export const CONTROL_STATUS: Record<
  SnapshotControl["status"],
  [string, string]
> = {
  passed: ["Выполнена", "pill-ok"],
  failed: ["Не выполнена", "pill-danger"],
  na: ["Не проверена", "pill-muted"],
};

export const COVERAGE_STATUS: Record<string, [string, string]> = {
  checked: ["Проверен", "pill-ok"],
  partial: ["Частично", "pill-warn"],
  unreachable: ["Недоступен", "pill-danger"],
  not_checked: ["Не проверен", "pill-muted"],
};

export const MODULE_LABELS: Record<string, string> = {
  discovery: "Обнаружение",
  vuln: "Уязвимости по сети",
  auth_inventory: "Пакеты по SSH",
  win_inventory: "Windows",
  config_audit: "Аудит конфигурации",
  cred_audit: "Аудит паролей",
};

/** «прогон №8 «Повторный…»» — подпись прогона для текста. */
export function runLabel(s: {
  run_id: number;
  run_name: string | null;
}): string {
  return s.run_name
    ? `прогон №${s.run_id} «${s.run_name}»`
    : `прогон №${s.run_id}`;
}

/** Текст сбоя проверки: заголовок находки или факта. */
export function failureText(f: CheckFailure["failures"][number]): string {
  if (f.vuln_id && f.title) return `${f.vuln_id}: ${f.title}`;
  return f.title ?? f.vuln_id ?? "нарушение";
}
