/** Методика оценки критичности уязвимостей (ФСТЭК России, 30.06.2025): типы и подписи. */

export interface Source {
  document?: string | null;
  clause?: string | null;
  appendix?: string | null;
  table?: string | null;
  row?: string | null;
  url?: string | null;
  note?: string | null;
}

export interface IndicatorValue {
  code: string;
  title: string;
  score: number;
  share_min?: number | null;
  share_max?: number | null;
}

export interface Indicator {
  code: string;
  group: "infr" | "at" | "imp";
  weight_symbol?: string;
  weight: number;
  title: string;
  multiple: "max" | "single";
  source?: Source;
  values: IndicatorValue[];
}

export interface Deadline {
  value: number;
  unit: "hours" | "days" | "weeks" | "months";
  text?: string;
}

export interface Level {
  code: string;
  title: string;
  condition?: string;
  min?: number | null;
  max?: number | null;
  min_inclusive?: boolean;
  max_inclusive?: boolean;
  deadline: Deadline;
  source?: Source;
}

export interface Group {
  code: "infr" | "at" | "imp";
  symbol: string;
  title: string;
  formula: string;
  source?: Source;
}

export type Inputs = Record<string, string | string[] | boolean>;

export interface Example {
  code: string;
  title: string;
  bdu_id?: string;
  inputs: Inputs;
  expected: Record<string, string>;
  source?: Source;
}

export interface Definition {
  formula: { text: string; source?: Source };
  rounding?: { digits: number; note?: string };
  cvss: { version: string; min: number; max: number; note?: string; source?: Source };
  groups: Group[];
  indicators: Indicator[];
  levels: Level[];
  certified_szi?: { level: string; text: string; source?: Source };
  remediation?: { text: string; source?: Source };
  compensating_measures?: { source?: Source; items: { code: string; title: string }[] };
  recalculation?: { text: string; source?: Source }[];
  examples?: Example[];
}

export interface TraceRow {
  indicator: string;
  group?: string;
  title: string;
  weight_symbol?: string;
  weight?: string;
  chosen?: { code: string; title: string; score: string }[];
  value?: string;
  value_title?: string;
  score: string;
  product?: string;
  rule?: string | null;
  source?: Source;
}

export interface Outcome {
  v: string;
  v_exact: string;
  level: { code: string; title: string; condition?: string; deadline: Deadline; source?: Source };
  level_by_v: string | null;
  groups: { infr: string; at: string; imp: string };
  cvss: string;
  certified_szi: boolean;
  trace: TraceRow[];
}

export interface MethodologyBrief {
  id: string;
  title: string;
  version: string;
  revision: number;
  origin: string;
  source: Source;
  verified: boolean;
  verified_by_name: string | null;
  verified_at: string | null;
  updated_at: string;
}

export interface Methodology extends MethodologyBrief {
  definition: Definition;
  definition_hash: string;
  examples: { code: string; title: string; inputs: Inputs; expected: Record<string, string>; outcome: Outcome; reproduced: boolean }[];
  revisions: { revision: number; changed_by_name: string | null; changed_at: string; comment: string | null; version: string | null }[];
}

export interface CalculateResult {
  methodology_id: string;
  version: string;
  revision: number;
  verified: boolean;
  outcome: Outcome;
}

export interface RefDocument {
  code: string;
  short: string;
  title: string;
  issuer: string | null;
  issued: string | null;
  number: string | null;
  url: string | null;
  status: "active" | "not_applicable";
  replaced_by: string | null;
  replaces: string[];
  source: Source;
  origin: string;
  verified: boolean;
  verified_by_name: string | null;
  verified_at: string | null;
  revision: number;
  updated_at: string;
}

export const DOC_STATUS: Record<string, string> = {
  active: "Применяется",
  not_applicable: "Не применяется",
};

// Родительный падеж после «до N»: единственное (1, 21, …) и множественное число.
const UNITS: Record<Deadline["unit"], [string, string]> = {
  hours: ["часа", "часов"],
  days: ["дня", "дней"],
  weeks: ["недели", "недель"],
  months: ["месяца", "месяцев"],
};

/** «до 24 часов», «до 7 дней», «до 4 недель», «до 4 месяцев». */
export function deadlineText(d: Deadline): string {
  const forms = UNITS[d.unit];
  if (!forms) return `до ${d.value} ${d.unit}`;
  const one = d.value % 10 === 1 && d.value % 100 !== 11;
  return `до ${d.value} ${one ? forms[0] : forms[1]}`;
}

/** Число с запятой: 4.75 → «4,75». */
export function decimal(v: string | number | null | undefined): string {
  if (v === null || v === undefined || v === "") return "—";
  return String(v).replace(".", ",");
}

/** Класс плашки уровня: critical, high, medium, low. */
export function levelClass(code: string): string {
  return `pill pill-sev pill-sev-${code}`;
}

export function sourceLine(s: Source | null | undefined): string {
  if (!s) return "";
  const parts: string[] = [];
  if (s.clause) parts.push(`п. ${s.clause}`);
  if (s.table) parts.push(`таблица ${s.table}${s.row ? `, строка ${s.row}` : ""}`);
  if (s.appendix) parts.push(`приложение${s.appendix === "1" ? "" : ` ${s.appendix}`}`);
  return parts.join("; ");
}

/** Пустые исходные данные калькулятора. */
export function emptyInputs(def: Definition): Inputs {
  const out: Inputs = { cvss: "" };
  for (const i of def.indicators) out[i.code] = [];
  out.certified_szi = false;
  return out;
}
