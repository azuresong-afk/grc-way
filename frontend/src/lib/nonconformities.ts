// План устранения несоответствий и заявки «Устранения» (задача 3.4).

export type NcKind = "measure" | "vuln";
export type NcState = "open" | "in_work" | "fixed" | "verified" | "decision" | "closed";
export type Method = "update" | "compensating";
export type UpdateOrigin = "foreign" | "opensource" | "domestic";
export type Priority = "high" | "medium" | "low";

export interface NcItem {
  id: string;
  kind: NcKind;
  ref: string;
  title: string;
  object_measure_id: string | null;
  object_vuln_id: string | null;
  source_status: string | null;
  source_status_title: string | null;
  measure_method: string | null;
  hosts: string[];
  details: string | null;
  v: string | null;
  level: string | null;
  level_title: string | null;
  assessed_at: string | null;
  deadline_at: string | null;
  certified_szi: boolean;
  priority: Priority | null;
  due_date: string | null;
  action: string | null;
  default_action: string;
  responsible: string | null;
  comment: string | null;
  method: Method | null;
  update_origin: UpdateOrigin | null;
  update_tested: boolean | null;
  compensating: string[];
  opened_at: string;
  closed_at: string | null;
  close_reason: string | null;
  state: NcState;
  state_title: string;
  overdue: boolean;
  send_blocker: string | null;
  resend: boolean;
  warnings: string[];
  vm_ticket_id: string | null;
  vm_status: string | null;
  vm_status_title: string | null;
  vm_status_at: string | null;
  vm_verified_result: string | null;
  vm_verified_at: string | null;
  vm_verified_run_id: string | null;
  ticket_url: string | null;
  sent_at: string | null;
  sent_by_name: string | null;
  updated_at: string;
  updated_by_name: string | null;
}

export interface NcEvent {
  at: string;
  kind: string;
  text: string;
  actor_name: string | null;
}

export interface NcDetail extends NcItem {
  history: NcEvent[];
}

export interface Plan {
  object_id: string;
  vm: { mode: "live" | "fixture"; source: string; project_id: string | null; events: boolean };
  compensating_measures: { code: string; title: string }[];
  counts: Record<string, number>;
  items: NcItem[];
}

export interface SendOut {
  sent: number;
  results: { id: string; ok: boolean; ticket_id: string | null; error: string | null }[];
}

export const STATE_PILL: Record<NcState, string> = {
  open: "pill-info",
  in_work: "pill-running",
  fixed: "pill-info",
  verified: "pill-ok",
  decision: "pill-warn",
  closed: "pill-muted",
};

export const PRIORITIES: Record<Priority, string> = { high: "Высокий", medium: "Средний", low: "Низкий" };
export const PRIORITY_PILL: Record<Priority, string> = {
  high: "pill pill-sev pill-sev-high",
  medium: "pill pill-sev pill-sev-medium",
  low: "pill pill-sev pill-sev-low",
};
export const METHODS: Record<Method, string> = { update: "Обновление", compensating: "Компенсирующие меры" };
export const UPDATE_ORIGINS: Record<UpdateOrigin, string> = {
  foreign: "Зарубежное ПО",
  opensource: "ПО с открытым кодом",
  domestic: "Российское ПО",
};
const UPDATE_ORIGIN_SHORT: Record<UpdateOrigin, string> = {
  foreign: "зарубежное ПО",
  opensource: "ПО с открытым кодом",
  domestic: "российское ПО",
};
export const VERIFY_RESULTS: Record<string, string> = {
  verified: "подтверждено",
  not_verified: "не подтверждено",
  partial: "подтверждено частично",
  unverified: "не проверено",
};

/** Можно отправить сейчас: нет запрета и пункт не отправлен или изменился после отправки. */
export function canSend(i: NcItem): boolean {
  return !i.send_blocker && (i.state === "open" || i.resend || i.state === "decision");
}

export function needsAttention(i: NcItem): boolean {
  return i.state !== "closed" && (i.overdue || i.state === "decision" || i.resend || i.warnings.length > 0);
}

export function methodShort(i: NcItem): string | null {
  if (i.kind !== "vuln") return null;
  if (i.method === "update") return i.update_origin ? `Обновление · ${UPDATE_ORIGIN_SHORT[i.update_origin]}` : "Обновление";
  if (i.method === "compensating") return `Компенсирующие: ${i.compensating.join(", ")}`;
  return null;
}
