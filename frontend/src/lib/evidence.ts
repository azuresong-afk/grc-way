// Ручные доказательства мер (задача 1.10): файл, интервью, осмотр; подтверждение меры.
import { apiFetch } from "./api";
import type { SnapshotBrief } from "./snapshots";

export type ManualKind = "file" | "interview" | "inspection";
export type FileCategory =
  | "document"
  | "screenshot"
  | "config"
  | "protocol"
  | "other";

export interface EvidenceFileInfo {
  id: string;
  name: string;
  ext: string;
  mime: string;
  size: number;
  sha256: string;
}

export interface ManualData {
  held_on?: string;
  participants?: string;
  place?: string;
  details?: string;
  category?: FileCategory;
}

export interface ManualEvidence {
  id: string;
  kind: ManualKind | "certificate" | "scanner" | "remediation";
  status: string | null;
  summary: string;
  data: ManualData;
  snapshot: SnapshotBrief | null;
  file: EvidenceFileInfo | null;
  created_at: string;
  created_by_name: string | null;
  withdrawn_at: string | null;
  withdrawn_by_name: string | null;
  withdraw_reason: string | null;
  in_confirmation: boolean;
}

export const KIND_LABELS: Record<ManualEvidence["kind"], string> = {
  file: "Файл",
  interview: "Интервью",
  inspection: "Осмотр",
  certificate: "Сертификат",
  scanner: "«Сканер»",
  remediation: "«Устранение»",
};

export const CATEGORY_LABELS: Record<FileCategory, string> = {
  document: "Документ",
  screenshot: "Скриншот",
  config: "Конфигурация",
  protocol: "Протокол",
  other: "Другое",
};

// Белый список сервера (app/domain/evidence_files.py) — для подсказки и поля выбора.
export const ACCEPT =
  ".pdf,.docx,.xlsx,.odt,.png,.jpg,.jpeg,.txt,.log,.conf,.cfg,.csv,.json,.xml,.zip";
export const ACCEPT_TEXT =
  "PDF, DOCX, XLSX, ODT, PNG, JPG, TXT, CSV, JSON, XML, ZIP";

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} Б`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} КБ`;
  return `${(bytes / (1024 * 1024)).toFixed(1).replace(".", ",")} МБ`;
}

/** Скачивание с токеном: fetch → blob → временная ссылка. Файл не открывается в окне. */
export async function downloadFile(f: EvidenceFileInfo): Promise<void> {
  const res = await apiFetch(`/files/${f.id}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = f.name;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

/** Мера оценена, не исключена и ещё не подтверждена испытателем. */
export function awaitsConfirmation(m: {
  status: string;
  adaptation: string;
  confirmed_at: string | null;
}): boolean {
  return (
    m.confirmed_at === null &&
    m.status !== "unassessed" &&
    m.adaptation !== "excluded"
  );
}
