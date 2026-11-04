// БДУ ФСТЭК России: угрозы (thrlist.xlsx), уязвимости (vullist.xlsx), загрузки выгрузок.

export type BduKind = "threats" | "vulns";
export type Exploit = "public" | "exists" | "unknown" | "none" | "other";
export type InWild = "yes" | "no" | "unknown" | "other";
export type ELevel = "in_wild" | "exploit" | "none";

export interface KindStatus {
  kind: BduKind;
  title: string;
  file_name: string;
  version: string | null;
  version_source: string | null;
  applied_at: string | null;
  applied_by_name: string | null;
  active: number;
  withdrawn: number;
  pending_id: string | null;
  criticality_last: number | null;
}

export type BduStatus = Record<BduKind, KindStatus>;

export type Change = "add" | "update" | "restore" | "withdraw";
export type Plain = string | number | boolean | null | string[] | Record<string, unknown>;

export interface ImportItem {
  key: string;
  change: Change;
  title: string | null;
  fields?: Record<string, [Plain, Plain]>;
  criticality?: boolean;
  cvss3_score?: number | null;
  exploit?: Exploit | null;
  in_wild?: InWild | null;
}

export interface ImportSummary {
  kind: BduKind;
  in_file: number;
  rows_in_file: number;
  add: number;
  update: number;
  restore: number;
  withdraw: number;
  unchanged: number;
  criticality: number;
  skipped: number;
  duplicates: number;
  cvss_mismatch: number;
  active_before: number;
  has_changes: boolean;
  items_shown: number;
  items_total: number;
  header_row: number;
  columns: Record<string, string>;
  title: string | null;
  crit_ids: string[];
}

export interface ImportBrief {
  id: string;
  kind: BduKind;
  file_name: string;
  file_size: number;
  export_version: string | null;
  version_source: string;
  version_source_title: string;
  status: "pending" | "applied" | "superseded";
  summary: ImportSummary;
  warnings: { code: string; text: string }[];
  created_at: string;
  created_by_name: string | null;
  applied_at: string | null;
  applied_by_name: string | null;
  applied: Record<string, number | boolean> | null;
}

export interface Import extends ImportBrief {
  items: ImportItem[];
  field_titles: Record<string, string>;
}

export interface Threat {
  code: string;
  number: number;
  title: string;
  description: string | null;
  source: string | null;
  target: string | null;
  conf: boolean | null;
  integ: boolean | null;
  avail: boolean | null;
  published_on: string | null;
  changed_on: string | null;
  status: string | null;
  first_version: string | null;
  changed_version: string | null;
  withdrawn_at: string | null;
}

export interface VulnBrief {
  bdu_id: string;
  title: string;
  vendor: string | null;
  product: string | null;
  cvss3_vector: string | null;
  cvss3_version: string | null;
  cvss3_score: number | null;
  cvss3_score_source: "bdu" | "computed" | null;
  exploit: Exploit | null;
  in_wild: InWild | null;
  e_level: ELevel;
  status: string | null;
  cve_ids: string[];
  changed_version: string | null;
  criticality_changed_at: string | null;
  withdrawn_at: string | null;
}

export interface Vuln extends VulnBrief {
  description: string | null;
  product_version: string | null;
  sw_type: string | null;
  platform: string | null;
  vuln_class: string | null;
  identified_on: string | null;
  published_on: string | null;
  severity: string | null;
  cvss_other: { cvss2?: { vector?: string; score?: number }; cvss4?: { vector?: string; score?: number } } | null;
  measures: string | null;
  exploit_raw: string | null;
  in_wild_raw: string | null;
  fix_info: string | null;
  links: string | null;
  cwe_ids: string[];
  other_ids: string | null;
  other_info: string | null;
  exploit_method: string | null;
  fix_method: string | null;
  first_version: string | null;
  criticality_changes: Record<string, [Plain, Plain]> | null;
  criticality_changed_version: string | null;
}

export const EXPLOIT: Record<Exploit, [string, string]> = {
  public: ["В открытом доступе", "pill-danger"],
  exists: ["Существует", "pill-warn"],
  unknown: ["Уточняется", "pill-muted"],
  none: ["Нет сведений", "pill-muted"],
  other: ["Иное", "pill-muted"],
};

export const IN_WILD: Record<InWild, [string, string]> = {
  yes: ["Эксплуатируется", "pill-danger"],
  no: ["Нет", "pill-muted"],
  unknown: ["Уточняется", "pill-muted"],
  other: ["Иное", "pill-muted"],
};

/** Строка таблицы 1 Методики 2025 (показатель E), подсказанная сведениями БДУ. */
export const E_LEVEL: Record<ELevel, string> = {
  in_wild: "Эксплуатируется в реальных атаках",
  exploit: "Имеются сведения о наличии эксплойта",
  none: "Отсутствуют сведения об эксплуатации",
};

export const CHANGE: Record<Change, [string, string]> = {
  add: ["Новая", "pill-ok"],
  update: ["Изменена", "pill-info"],
  restore: ["Возвращена", "pill-info"],
  withdraw: ["Нет в выгрузке", "pill-warn"],
};

export const IMPORT_STATUS: Record<ImportBrief["status"], [string, string]> = {
  pending: ["Ждёт применения", "pill-warn"],
  applied: ["Применена", "pill-ok"],
  superseded: ["Устарела", "pill-muted"],
};

/** «2026-11-01» → «01.11.2026». */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso);
  return m ? `${m[3]}.${m[2]}.${m[1]}` : iso;
}

/** Значение поля для показа «было → стало». */
export function plainText(v: Plain, field?: string): string {
  if (v === null || v === "") return "";
  if (field === "exploit" && typeof v === "string") return EXPLOIT[v as Exploit]?.[0] ?? v;
  if (field === "in_wild" && typeof v === "string") return IN_WILD[v as InWild]?.[0] ?? v;
  if (typeof v === "boolean") return v ? "да" : "нет";
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "object") return JSON.stringify(v);
  if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v)) return formatDate(v);
  return String(v);
}

export function formatSize(bytes: number): string {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} КБ`;
  return `${(bytes / (1024 * 1024)).toFixed(1).replace(".", ",")} МБ`;
}
