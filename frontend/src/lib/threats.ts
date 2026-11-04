// Справочник Методики оценки угроз 2021: последствия, нарушители, тактики и техники.
import type { Source } from "./classification";

export type ThreatKind =
  | "consequence_type"
  | "consequence"
  | "capability"
  | "intruder"
  | "tactic"
  | "technique";

export interface ThreatItem {
  code: string;
  kind: ThreatKind;
  parent_code: string | null;
  position: number;
  title: string;
  description: string | null;
  attrs: { capability?: string; category?: string };
  source: Source;
  origin: string;
  revision: number;
  verified: boolean;
  verified_by_name: string | null;
  verified_at: string | null;
  updated_at: string;
}

export interface ThreatItemDetail extends ThreatItem {
  revisions: {
    revision: number;
    changed_by_name: string | null;
    changed_at: string;
    comment: string | null;
    data: Partial<ThreatItem>;
  }[];
}

export interface ThreatRefs {
  document: { document?: string; url?: string } | null;
  total: number;
  unverified: number;
  kinds: Record<ThreatKind, { total: number; unverified: number }>;
  items: ThreatItem[];
}

export interface BulkVerifyResult {
  verified: string[];
  skipped: Record<string, string>;
}

export const KIND_TITLES: Record<ThreatKind, string> = {
  consequence_type: "Вид негативных последствий",
  consequence: "Негативное последствие",
  capability: "Уровень возможностей нарушителя",
  intruder: "Вид нарушителя",
  tactic: "Тактика",
  technique: "Техника",
};

/** Вкладки экрана: какие виды записей на них показаны. */
export const SECTIONS = [
  {
    key: "consequences",
    title: "Негативные последствия",
    kinds: ["consequence_type", "consequence"],
  },
  { key: "intruders", title: "Нарушители", kinds: ["capability", "intruder"] },
  {
    key: "tactics",
    title: "Тактики и техники",
    kinds: ["tactic", "technique"],
  },
] as const satisfies readonly {
  key: string;
  title: string;
  kinds: readonly ThreatKind[];
}[];

export type SectionKey = (typeof SECTIONS)[number]["key"];

/** Следующий свободный код дочерней записи: У1 → У1.12, Т3 → Т3.1. */
export function nextChildCode(parent: string, items: ThreatItem[]): string {
  const used = new Set(items.map((i) => i.code));
  let n = items.filter((i) => i.parent_code === parent).length + 1;
  while (used.has(`${parent}.${n}`)) n += 1;
  return `${parent}.${n}`;
}

/** Следующий код вида нарушителя: НВ14. */
export function nextIntruderCode(items: ThreatItem[]): string {
  const used = new Set(items.map((i) => i.code));
  let n = items.filter((i) => i.kind === "intruder").length + 1;
  while (used.has(`НВ${n}`)) n += 1;
  return `НВ${n}`;
}
