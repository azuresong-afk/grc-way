// Документы комплекта объекта (задача 3.1): карта данных, версии, скачивание.
import { apiFetch } from "./api";

export type FieldState = "filled" | "empty" | "partial" | "na";
export type FieldTab = "project" | "description" | "classification" | "composition" | "szi";

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
}

export interface DocBrief {
  id: string;
  doc_type: string;
  title: string;
  version: number;
  status: "draft" | "review" | "approved";
  status_title: string;
  watermark: boolean;
  watermark_reasons: string[];
  counts: DocCounts;
  docx_size: number;
  pdf_size: number | null;
  pdf_error: string | null;
  created_at: string;
  created_by_name: string | null;
}

export interface DocFull extends DocBrief {
  template_name: string;
  context_hash: string;
  fields: DocField[];
  unverified: Unverified[];
}

export interface DocType {
  code: string;
  title: string;
  description: string;
  template: string;
  template_found: boolean;
  counts: DocCounts;
  watermark_reasons: string[];
  changed: boolean;
  latest: DocBrief | null;
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
  sees_drafts: boolean;
}

export const TAB_TITLES: Record<FieldTab, string> = {
  project: "Проект",
  description: "Описание",
  classification: "Классификация",
  composition: "Состав",
  szi: "СЗИ",
};

export const STATE_PILL: Record<FieldState, [string, string]> = {
  filled: ["pill-ok", "Заполнено"],
  partial: ["pill-warn", "Частично"],
  empty: ["pill-danger", "Пусто"],
  na: ["pill-muted", "Нет данных"],
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
  const res = await apiFetch(`/documents/${d.id}/file?format=${format}`);
  const name = dispositionName(res.headers.get("Content-Disposition"), `${d.title} v${d.version}.${format}`);
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
