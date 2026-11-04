// Объекты проекта: типы ответа API и подписи.

export type Kind = "gis" | "ispdn" | "kii" | "other";
export type Regime = "117" | "21" | "239";

export interface Responsible {
  name: string;
  position?: string | null;
  role?: string | null;
  phone?: string | null;
  email?: string | null;
}

export interface Interconnection {
  system: string;
  owner?: string | null;
  direction: "in" | "out" | "both";
  channel?: string | null;
  description?: string | null;
}

export interface Segment {
  id: string;
  name: string;
  description: string | null;
  scanner_group: string | null;
  host_count: number;
}

export interface ObjectBrief {
  id: string;
  project_id: string;
  kind: Kind;
  name: string;
  regime: Regime | null;
  status: "active" | "archived";
  internet: boolean;
  host_count: number;
  segment_count: number;
  updated_at: string;
  // Утверждённая классификация по текущему режиму, иначе последний черновик.
  classification?: {
    id: string;
    result: string;
    short: string;
    result_label: string;
    status: "approved" | "draft";
  } | null;
}

export interface ObjectFull extends ObjectBrief {
  purpose: string | null;
  boundaries: string | null;
  interconnections: Interconnection[];
  responsible: Responsible[];
  created_at: string;
  scanner_synced_at: string | null;
  scanner_engagement_id: number | null;
  segments: Segment[];
}

export interface Host {
  id: string;
  address: string;
  hostname: string | null;
  role: string | null;
  segment_id: string | null;
  os: string | null;
  os_family: string | null;
  source: "manual" | "scanner";
  scanner_asset_id: number | null;
  scanner_groups: string[];
  criticality: string | null;
  owner: string | null;
  last_seen_at: string | null;
  scanner_missing: boolean;
  synced_at: string | null;
}

export interface Asset {
  id: number;
  address: string;
  hostname: string | null;
  os: string | null;
  os_family: string | null;
  criticality: string | null;
  owner: string | null;
  groups: string[];
  last_seen_at: string | null;
  in_object: boolean;
  other_objects: string[];
}

export interface AssetsResponse {
  engagement_id: number;
  mode: string;
  source: string;
  assets: Asset[];
}

export interface SyncResult {
  added: string[];
  updated: string[];
  linked: string[];
  missing: string[];
  segments_created: string[];
  hosts: Host[];
}

export const KIND_LABELS: Record<Kind, string> = {
  gis: "ГИС",
  ispdn: "ИСПДн",
  kii: "ЗО КИИ",
  other: "Иная система",
};

export const KIND_HINTS: Record<Kind, string> = {
  gis: "Государственная информационная система",
  ispdn: "Информационная система персональных данных",
  kii: "Значимый объект критической информационной инфраструктуры",
  other: "Иная информационная или автоматизированная система",
};

export const REGIME_LABELS: Record<Regime, string> = {
  "117": "Приказ ФСТЭК №117",
  "21": "Приказ ФСТЭК №21",
  "239": "Приказ ФСТЭК №239",
};

export const DEFAULT_REGIME: Record<Kind, Regime | null> = {
  gis: "117",
  ispdn: "21",
  kii: "239",
  other: null,
};

export const DIRECTION_LABELS: Record<Interconnection["direction"], string> = {
  in: "входящий",
  out: "исходящий",
  both: "двусторонний",
};

export const CRITICALITY_LABELS: Record<string, string> = {
  low: "Низкая",
  medium: "Средняя",
  high: "Высокая",
  critical: "Критичная",
};

/** Сортировка IP как чисел: 10.0.0.9 раньше 10.0.0.10. */
export function compareAddress(a: string, b: string): number {
  const pa = a.includes(":") ? null : a.split(".").map(Number);
  const pb = b.includes(":") ? null : b.split(".").map(Number);
  if (pa && pb) {
    for (let i = 0; i < 4; i++) if (pa[i] !== pb[i]) return (pa[i] ?? 0) - (pb[i] ?? 0);
    return 0;
  }
  if (pa) return -1;
  if (pb) return 1;
  return a.localeCompare(b);
}

/** Грубая проверка IP на клиенте; точную делает сервер. */
export function looksLikeIp(s: string): boolean {
  const v = s.trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return v.split(".").every((x) => Number(x) <= 255);
  return /^[0-9a-f:]+$/i.test(v) && v.includes(":");
}
