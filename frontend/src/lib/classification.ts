// Классификация: таблица-данные, расчёт и его трасса. Код таблицу только показывает.

export interface Option {
  value: string;
  label: string;
  help?: string;
}

export interface InputDef {
  key: string;
  label: string;
  help?: string;
  group?: string;
  options: Option[];
}

export interface Source {
  document?: string;
  clause?: string | null;
  appendix?: string | null;
  url?: string | null;
  note?: string | null;
}

export interface Row {
  id: string;
  when: Record<string, string | string[]>;
  value: string;
  source?: Source;
  note?: string;
}

export interface StepDef {
  key: string;
  label: string;
  method: "first_match" | "max";
  values?: Option[];
  rows?: Row[];
  fields?: string[];
  order?: string[];
  source?: Source;
  note?: string;
}

export interface Definition {
  groups?: { key: string; title: string }[];
  inputs: InputDef[];
  steps: StepDef[];
  result: { key: string; label: string; values: Option[] };
}

export interface TableBrief {
  regime: string;
  regime_title: string;
  title: string;
  version: string;
  revision: number;
  origin: string;
  source: Source;
  verified: boolean;
  verified_by_name: string | null;
  verified_at: string | null;
  updated_at: string;
  gaps: number;
}

export interface Table extends TableBrief {
  definition: Definition;
  definition_hash: string;
  revisions: {
    revision: number;
    changed_by_name: string | null;
    changed_at: string;
    comment: string | null;
    version: string | null;
  }[];
}

export interface TraceStep {
  key: string;
  label: string;
  method: string;
  value: string;
  row_id: string | null;
  matched: Record<string, string>;
  source: Source | null;
  note: string | null;
}

export interface Outcome {
  regime: string;
  result: string;
  result_label: string;
  values: Record<string, string>;
  trace: TraceStep[];
  table_version: string;
  table_revision: number;
  table_verified: boolean;
  table_source: Source;
}

export type ClassStatus = "draft" | "approved" | "superseded";

export interface Classification {
  id: string;
  object_id: string;
  regime: string;
  inputs: Record<string, string>;
  result: string;
  result_label: string;
  values: Record<string, string>;
  trace: TraceStep[];
  justification: string | null;
  table_version: string;
  table_revision: number;
  table_verified: boolean;
  status: ClassStatus;
  created_at: string;
  created_by: string | null;
  created_by_name: string | null;
  approved_at: string | null;
  approved_by_name: string | null;
  approval_comment: string | null;
  unverified_acknowledged: boolean;
  superseded_at: string | null;
  table_changed: boolean;
}

export interface ClassificationDetail extends Classification {
  table_snapshot: Definition;
  table_source: Source;
  reproducible: boolean;
}

export const STATUS_LABELS: Record<ClassStatus, string> = {
  draft: "Черновик",
  approved: "Утверждена",
  superseded: "Заменена",
};

export const STATUS_PILL: Record<ClassStatus, string> = {
  draft: "pill-warn",
  approved: "pill-ok",
  superseded: "pill-muted",
};

export const ORIGIN_LABELS: Record<string, string> = {
  stub: "Заглушка",
  official: "Из официального текста",
  local: "Изменено в интерфейсе",
};

/** Подпись значения: вариант поля исходных данных, значение шага или итог. */
export function valueLabel(def: Definition, key: string, value: string): string {
  const input = def.inputs.find((i) => i.key === key);
  const fromInput = input?.options.find((o) => o.value === value)?.label;
  if (fromInput) return fromInput;
  const step = def.steps.find((s) => s.key === key);
  const fromStep = step?.values?.find((v) => v.value === value)?.label;
  if (fromStep) return fromStep;
  if (key === def.result.key) {
    const r = def.result.values.find((v) => v.value === value)?.label;
    if (r) return r;
  }
  return value;
}

/** Подпись поля: исходные данные или шаг расчёта. */
export function fieldLabel(def: Definition, key: string): string {
  return (
    def.inputs.find((i) => i.key === key)?.label ?? def.steps.find((s) => s.key === key)?.label ?? key
  );
}

/** Условие строки таблицы человеческим языком. */
export function describeWhen(def: Definition, when: Row["when"]): string[] {
  return Object.entries(when).map(([f, allowed]) => {
    const vals = (Array.isArray(allowed) ? allowed : [allowed]).map((v) => valueLabel(def, f, String(v)));
    return `${fieldLabel(def, f)}: ${vals.join(" или ")}`;
  });
}

export function sourceText(s: Source | null | undefined): string {
  if (!s) return "";
  return [s.document, s.clause, s.appendix].filter(Boolean).join(", ");
}

/** Шаги мастера: группы исходных данных по порядку (поля без группы — в отдельный шаг). */
export function wizardSteps(def: Definition): { key: string; title: string; inputs: InputDef[] }[] {
  const groups = def.groups ?? [];
  const out = groups.map((g) => ({
    key: g.key,
    title: g.title,
    inputs: def.inputs.filter((i) => i.group === g.key),
  }));
  const rest = def.inputs.filter((i) => !groups.some((g) => g.key === i.group));
  if (rest.length) out.push({ key: "_rest", title: "Исходные данные", inputs: rest });
  return out.filter((s) => s.inputs.length > 0);
}
