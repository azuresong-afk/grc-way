// Документы комплекта объекта (задачи 3.1–3.3): карта данных, версии, скачивание,
// шрифт комплекта, свой шаблон документа, согласование и сравнение версий.
import { apiFetch } from "./api";

export type FieldState = "filled" | "empty" | "partial" | "na";
export type FieldTab =
  | "project"
  | "description"
  | "classification"
  | "composition"
  | "szi"
  | "measures"
  | "threats"
  | "vulns";
export type FontCode = "astra" | "inter";
export type DocStatus = "draft" | "review" | "approved" | "superseded";

export interface DocField {
  key: string;
  title: string;
  source: string;
  tab: FieldTab;
  required: boolean;
  state: FieldState;
  value: string | null;
  total: number | null;
  missing: number | null;
  missing_examples: string[] | null;
}

export interface DocCounts {
  total: number;
  empty: number;
  required_empty: number;
}

export interface Unverified {
  title: string;
  note: string;
  section?: string;
}

export interface DocBrief {
  id: string;
  doc_type: string;
  title: string;
  version: number;
  status: DocStatus;
  status_title: string;
  watermark: boolean;
  watermark_reasons: string[];
  counts: DocCounts;
  docx_size: number;
  pdf_size: number | null;
  pdf_error: string | null;
  created_at: string;
  created_by_name: string | null;
  template_name: string;
  template_custom: boolean;
  font: FontCode | null;
  font_title: string | null;
  submitted_at: string | null;
  submitted_by_name: string | null;
  approved_at: string | null;
  approved_by_name: string | null;
  approval_comment: string | null;
  unverified_acknowledged: boolean;
  superseded_at: string | null;
}

export type ReviewAction = "submit" | "return" | "approve" | "supersede";

export interface DocReview {
  action: ReviewAction;
  from_status: DocStatus;
  to_status: DocStatus;
  comment: string | null;
  actor_name: string | null;
  at: string;
}

export interface DocActions {
  submit: boolean;
  send_back: boolean;
  approve: boolean;
  approve_blocker: string | null;
}

export interface DocFull extends DocBrief {
  context_hash: string;
  fields: DocField[];
  unverified: Unverified[];
  reviews: DocReview[];
  actions: DocActions;
  siblings: DocBrief[];
}

export interface FieldChange {
  key: string;
  title: string;
  tab: FieldTab | null;
  before: string | null;
  after: string | null;
  state_before: FieldState | null;
  state_after: FieldState | null;
}

export interface DiffHunk {
  old_start: number;
  new_start: number;
  lines: { op: "same" | "add" | "del"; text: string }[];
}

export interface DocCompare {
  old: DocBrief;
  new: DocBrief;
  meta: { title: string; before: string | null; after: string | null }[];
  fields: FieldChange[];
  hunks: DiffHunk[];
  added: number;
  removed: number;
  truncated: boolean;
  text_error: string | null;
}

export interface TemplateRef {
  custom: boolean;
  name: string;
  id: string | null;
  uploaded_at: string | null;
  uploaded_by_name: string | null;
  comment: string | null;
}

export interface DocType {
  code: string;
  title: string;
  description: string;
  template: string;
  template_found: boolean;
  template_ref: TemplateRef;
  font: FontCode | null;
  counts: DocCounts;
  watermark_reasons: string[];
  changed: boolean;
  latest: DocBrief | null;
  approved: DocBrief | null;
  versions: DocBrief[];
}

export interface DocTypeDetail extends DocType {
  fields: DocField[];
  unverified: Unverified[];
}

export interface DocumentsList {
  types: DocType[];
  pdf_available: boolean;
  can_edit: boolean;
  can_approve: boolean;
  sees_drafts: boolean;
  font: FontCode;
  fonts: { code: FontCode; title: string }[];
}

export interface TemplateRow {
  id: string;
  doc_type: string;
  name: string;
  size: number;
  variables: string[];
  active: boolean;
  comment: string | null;
  uploaded_at: string;
  uploaded_by_name: string | null;
  deactivated_at: string | null;
  deactivated_by_name: string | null;
}

export interface TemplateType {
  code: string;
  title: string;
  builtin: string;
  active: TemplateRow | null;
  history: TemplateRow[];
}

export interface TemplatesList {
  types: TemplateType[];
  can_manage: boolean;
  allowed_names: string[];
}

export const TAB_TITLES: Record<FieldTab, string> = {
  project: "Проект",
  description: "Описание",
  classification: "Классификация",
  composition: "Состав",
  szi: "СЗИ",
  measures: "Меры",
  threats: "Угрозы",
  vulns: "Уязвимости",
};

export const STATE_PILL: Record<FieldState, [string, string]> = {
  filled: ["pill-ok", "Заполнено"],
  partial: ["pill-warn", "Частично"],
  empty: ["pill-danger", "Пусто"],
  na: ["pill-muted", "Нет данных"],
};

export const STATUS_PILL: Record<DocStatus, string> = {
  draft: "pill-muted",
  review: "pill-info",
  approved: "pill-ok",
  superseded: "pill-muted",
};

export const REVIEW_TITLES: Record<ReviewAction, string> = {
  submit: "Отправлен на согласование",
  return: "Возвращён в проект",
  approve: "Утверждён",
  supersede: "Заменён новой версией",
};

/** Пустое или частично пустое поле — его нужно заполнить. */
export function isGap(f: DocField): boolean {
  return f.state === "empty" || f.state === "partial";
}

/** Ссылка на место, где поле заполняют. */
export function fieldLink(f: DocField, objectId: string, projectId: string): string {
  if (f.tab === "project") return `/projects/${projectId}`;
  return f.tab === "description" ? `/objects/${objectId}` : `/objects/${objectId}?tab=${f.tab}`;
}

/** Имя файла из Content-Disposition (filename* в UTF-8 приоритетнее). */
export function dispositionName(header: string | null, fallback: string): string {
  if (!header) return fallback;
  const star = /filename\*=UTF-8''([^;]+)/i.exec(header);
  if (star?.[1]) {
    try {
      return decodeURIComponent(star[1]);
    } catch {
      // битая кодировка — берём простое имя
    }
  }
  const plain = /filename="([^"]+)"/i.exec(header);
  return plain?.[1] ?? fallback;
}

/** Скачивание версии с токеном: fetch → blob → временная ссылка. */
export async function downloadDocument(d: DocBrief, format: "docx" | "pdf"): Promise<void> {
  await downloadFile(`/documents/${d.id}/file?format=${format}`, `${d.title} v${d.version}.${format}`);
}

/** Скачивание файла API с токеном (документ, шаблон). */
export async function downloadFile(path: string, fallback: string): Promise<void> {
  const res = await apiFetch(path);
  const name = dispositionName(res.headers.get("Content-Disposition"), fallback);
  const url = URL.createObjectURL(await res.blob());
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
