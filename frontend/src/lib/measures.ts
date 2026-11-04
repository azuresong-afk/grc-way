// Набор мер объекта: базовый по классу + адаптация; процент реализации считает сервер.
import type { SnapshotBrief } from "./snapshots";

export type MeasureStatus =
  | "implemented"
  | "partial"
  | "not_implemented"
  | "not_applicable"
  | "unassessed";
export type AdaptationKind = "none" | "excluded" | "compensated";

export interface ObjectMeasure {
  id: string;
  profile_id: string;
  measure_id: string;
  group_code: string;
  title: string;
  origin: "baseline" | "added";
  adaptation: AdaptationKind;
  adaptation_reason: string | null;
  compensating_ids: string[];
  compensates: string[];
  status: MeasureStatus;
  effective_status: MeasureStatus | null;
  method: "auto" | "manual" | "mixed";
  checks: string[];
  levels: string[];
  in_reference: boolean;
  verified: boolean;
  owner_id: string | null;
  owner_name: string | null;
  comment: string | null;
  adapted_at: string | null;
  adapted_by_name: string | null;
  status_at: string | null;
  status_by_name: string | null;
  status_source: "auto" | "manual" | null;
  auto_status: Exclude<MeasureStatus, "not_applicable"> | null;
  auto_note: string | null;
  auto_snapshot_id: string | null;
  updated_at: string;
}

export interface StatsBucket {
  total: number;
  implemented: number;
  partial: number;
  not_implemented: number;
  unassessed: number;
  excluded: number;
  not_applicable: number;
  compensated: number;
  score: number;
  percent: number | null;
}

export interface Stats {
  total: StatsBucket;
  auto: StatsBucket;
  manual: StatsBucket;
}

export interface AdaptationVersion {
  id: string;
  version: number;
  classification_id: string | null;
  profile_id: string;
  level: string;
  level_label: string;
  status: "draft" | "approved" | "superseded";
  created_at: string;
  created_by_name: string | null;
  edits: number;
  updated_at: string;
  editor_ids: string[];
  approved_at: string | null;
  approved_by_name: string | null;
  approval_comment: string | null;
  unverified_acknowledged: boolean;
  superseded_at: string | null;
  counts: {
    total: number;
    excluded: number;
    compensated: number;
    added: number;
  } | null;
}

export interface ClassRef {
  id: string;
  result: string;
  result_label: string;
  status: string;
}

export interface MeasureSet {
  state: "no_regime" | "no_profile" | "no_class" | "not_built" | "built";
  profile_id: string | null;
  profile_short: string | null;
  level_label: string | null;
  classification: ClassRef | null;
  adaptation: AdaptationVersion | null;
  class_changed: boolean;
  rebuild_needed: boolean;
  plan_counts: Record<string, number> | null;
  stats: Stats | null;
  partial_weight: number;
  groups: { code: string; title: string; total: number }[];
  counts: {
    total: number;
    baseline: number;
    added: number;
    excluded: number;
    compensated: number;
  };
  unverified: number;
  approve_blockers: string[];
  snapshot: SnapshotBrief | null;
}

export interface PlanItem {
  measure_id: string;
  title: string;
  group_code: string;
  assessed: boolean;
}

export interface Plan {
  classification: ClassRef;
  profile_id: string;
  level: string;
  add: PlanItem[];
  remove: PlanItem[];
  promote: PlanItem[];
  reset: PlanItem[];
  foreign: string[];
  unchanged: number;
  empty: boolean;
  changes: boolean;
}

export const STATUS_LABELS: Record<MeasureStatus, string> = {
  implemented: "Реализована",
  partial: "Частично",
  not_implemented: "Не реализована",
  not_applicable: "Не применима",
  unassessed: "Не оценена",
};

export const STATUS_PILL: Record<MeasureStatus, string> = {
  implemented: "pill-ok",
  partial: "pill-warn",
  not_implemented: "pill-danger",
  not_applicable: "pill-muted",
  unassessed: "pill-muted",
};

export const STATUS_ORDER: MeasureStatus[] = [
  "unassessed",
  "implemented",
  "partial",
  "not_implemented",
  "not_applicable",
];

export const METHOD_LABELS: Record<ObjectMeasure["method"], string> = {
  auto: "«Сканер»",
  manual: "Вручную",
  mixed: "Смешанная",
};

export const ADAPTATION_STATUS_LABELS: Record<
  AdaptationVersion["status"],
  string
> = {
  draft: "Не утверждена",
  approved: "Утверждена",
  superseded: "Заменена",
};

/** Проценты без дробной части, если она не важна: 0 < x < 1 → «<1». */
export function formatPercent(p: number | null | undefined): string {
  if (p === null || p === undefined) return "—";
  if (p > 0 && p < 1) return "<1 %";
  if (p < 100 && p > 99) return ">99 %";
  return `${Math.round(p)} %`;
}

/** Части полосы реализации в процентах знаменателя. */
export function barParts(
  b: StatsBucket,
): { key: string; value: number; label: string }[] {
  if (b.total === 0) return [];
  return [
    {
      key: "implemented",
      value: b.implemented,
      label: STATUS_LABELS.implemented,
    },
    { key: "partial", value: b.partial, label: STATUS_LABELS.partial },
    {
      key: "not_implemented",
      value: b.not_implemented,
      label: STATUS_LABELS.not_implemented,
    },
    { key: "unassessed", value: b.unassessed, label: STATUS_LABELS.unassessed },
  ]
    .filter((p) => p.value > 0)
    .map((p) => ({ ...p, value: (p.value / b.total) * 100 }));
}

/** Короткая подпись адаптации меры для строки таблицы. */
export function adaptationNote(m: ObjectMeasure): string | null {
  if (m.adaptation === "excluded")
    return `Исключена: ${m.adaptation_reason ?? ""}`;
  if (m.adaptation === "compensated")
    return `Компенсирована мерами ${m.compensating_ids.join(", ")}`;
  if (m.origin === "added") return `Дополнение: ${m.adaptation_reason ?? ""}`;
  return null;
}

/** Статус поставлен вручную и расходится с предложением «Сканера». */
export function differsFromScanner(m: ObjectMeasure): boolean {
  return (
    m.auto_status !== null &&
    m.status_source === "manual" &&
    m.status !== m.auto_status
  );
}
