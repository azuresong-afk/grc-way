// СЗИ: реестр сертифицированных СЗИ (загрузки CSV/XLSX) и СЗИ объекта.

import type { Change, Plain } from "./bdu";

export type CertState =
  | "expired"
  | "terminated"
  | "suspended"
  | "withdrawn"
  | "expiring"
  | "not_found"
  | "no_date"
  | "valid"
  | "uncertified";
export type Level = "bad" | "warn" | "ok" | "none";

export interface RegistryStatus {
  version: string | null;
  version_source: string | null;
  applied_at: string | null;
  applied_by_name: string | null;
  active: number;
  withdrawn: number;
  expired: number;
  expiring: number;
  pending_id: string | null;
  expiry_days: number;
}

export interface SziImportItem {
  key: string;
  change: Change;
  title: string | null;
  fields?: Record<string, [Plain, Plain]>;
  validity?: boolean;
  valid_to?: string | null;
  trust_level?: number | null;
}

export interface SziImportBrief {
  id: string;
  file_name: string;
  file_size: number;
  file_ext: "csv" | "xlsx";
  export_version: string | null;
  version_source: string;
  version_source_title: string;
  status: "pending" | "applied" | "superseded";
  summary: {
    in_file: number;
    add: number;
    update: number;
    restore: number;
    withdraw: number;
    unchanged: number;
    validity: number;
    has_changes: boolean;
    items_shown: number;
    items_total: number;
    title: string | null;
  };
  warnings: { code: string; text: string }[];
  created_at: string;
  created_by_name: string | null;
  applied_at: string | null;
  applied_by_name: string | null;
  applied: Record<string, number | boolean> | null;
}

export interface SziImport extends SziImportBrief {
  items: SziImportItem[];
  field_titles: Record<string, string>;
}

export interface CertBrief {
  cert_number: string;
  name: string;
  registered_on: string | null;
  valid_to: string | null;
  valid_to_raw: string | null;
  trust_level: number | null;
  profiles: string[];
  cert_status: "active" | "suspended" | "terminated";
  support_until: string | null;
  applicant: string | null;
  changed_version: string | null;
  withdrawn_at: string | null;
}

export interface Cert extends CertBrief {
  requirements: string | null;
  scheme: string | null;
  lab: string | null;
  cert_body: string | null;
  applicant_details: string | null;
  support_raw: string | null;
  note: string | null;
  first_version: string | null;
}

export interface ObjectSzi {
  id: string;
  object_id: string;
  name: string;
  kind: string;
  kind_title: string;
  vendor: string | null;
  version: string | null;
  cert_number: string | null;
  cert_valid_to: string | null;
  trust_level: number | null;
  protection_class: string | null;
  placement: string | null;
  measure_ids: string[];
  measures: { measure_id: string; title: string | null; state: "in_set" | "excluded" | "missing" }[];
  comment: string | null;
  state: CertState;
  state_title: string;
  level: Level;
  valid_to: string | null;
  valid_to_source: "registry" | "manual" | null;
  days_left: number | null;
  registry_match: "found" | "withdrawn" | "not_found" | "not_loaded" | "no_number";
  effective_trust_level: number | null;
  support_ended: boolean;
  notes: string[];
  registry: {
    cert_number: string;
    name: string;
    valid_to: string | null;
    trust_level: number | null;
    profiles: string[];
    cert_status: string;
    support_until: string | null;
    withdrawn: boolean;
  } | null;
  created_at: string;
  created_by_name: string | null;
  updated_at: string;
  updated_by_name: string | null;
}

export interface SziCounts {
  total: number;
  bad: number;
  expiring: number;
  check: number;
  uncertified: number;
}

export interface SziList {
  items: ObjectSzi[];
  counts: SziCounts;
  expiry_days: number;
  registry_version: string | null;
  registry_loaded: boolean;
  kinds: Record<string, string>;
  states: Record<CertState, [string, Level]>;
}

export const LEVEL_PILL: Record<Level, string> = {
  bad: "pill-danger",
  warn: "pill-warn",
  ok: "pill-ok",
  none: "pill-muted",
};

export const CERT_STATUS: Record<CertBrief["cert_status"], [string, string]> = {
  active: ["Действует", "pill-ok"],
  suspended: ["Приостановлен", "pill-danger"],
  terminated: ["Прекращён", "pill-danger"],
};

export const REGISTRY_MATCH: Record<ObjectSzi["registry_match"], string> = {
  found: "есть в реестре",
  withdrawn: "исключён из реестра",
  not_found: "нет в загруженном реестре",
  not_loaded: "реестр не загружен",
  no_number: "без сертификата",
};

/** «через 45 дн.», «истёк 30 дн. назад», «сегодня». */
export function daysText(days: number | null): string {
  if (days === null) return "";
  if (days === 0) return "истекает сегодня";
  if (days < 0) return `истёк ${-days} дн. назад`;
  return `осталось ${days} дн.`;
}
