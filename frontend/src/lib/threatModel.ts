// Модель угроз объекта по Методике 2021: шаги мастера, угрозы БДУ, прогресс.

export type StepKey = "consequences" | "objects" | "intruders" | "methods" | "scenarios" | "threats";
export type DataStep = Exclude<StepKey, "threats">;
export type ModelStatus = "draft" | "approved" | "superseded";

export interface ConsequenceItem {
  code: string;
  justification?: string;
}
export interface ImpactObject {
  key: string;
  name: string;
  description?: string;
  hosts: string[];
  impacts: string[];
  consequences: string[];
}
export interface IntruderItem {
  code: string;
  relevant: boolean;
  capability?: string;
  justification?: string;
}
export interface MethodItem {
  code: string;
  interfaces?: string;
  objects: string[];
  intruders: string[];
}
export interface ScenarioItem {
  tactic: string;
  techniques: string[];
  note?: string;
}

export interface Steps {
  consequences: { items: ConsequenceItem[]; note?: string };
  objects: { items: ImpactObject[]; note?: string };
  intruders: { items: IntruderItem[]; note?: string };
  methods: { items: MethodItem[]; note?: string };
  scenarios: { items: ScenarioItem[]; note?: string };
}

export interface StepProgress {
  key: StepKey;
  title: string;
  done: boolean;
  count: number;
  problems: string[];
}

export interface Progress {
  steps: StepProgress[];
  done: number;
  total: number;
  ready: boolean;
}

export interface Hint {
  categories: string[];
  potentials: string[];
}

export type LinkKey = "intruders" | "objects" | "consequences" | "methods" | "tactics";

export interface ModelThreat {
  code: string;
  title: string | null;
  description: string | null;
  source: string | null;
  target: string | null;
  conf: boolean | null;
  integ: boolean | null;
  avail: boolean | null;
  withdrawn: boolean;
  in_bdu: boolean;
  hint: Hint;
  relevant: boolean | null;
  justification: string | null;
  intruders: string[];
  objects: string[];
  consequences: string[];
  methods: string[];
  tactics: string[];
  linked_findings: unknown[];
  updated_at: string;
  updated_by_name: string | null;
}

export interface ModelBrief {
  id: string;
  object_id: string;
  version: number;
  status: ModelStatus;
  based_on: string | null;
  created_at: string;
  created_by: string | null;
  created_by_name: string | null;
  editor_ids: string[];
  edits: number;
  updated_at: string;
  approved_at: string | null;
  approved_by_name: string | null;
  approval_comment: string | null;
  unverified_acknowledged: boolean;
  superseded_at: string | null;
  considered: number;
  relevant: number;
}

export interface ModelDetail extends ModelBrief {
  steps: Steps;
  threats: ModelThreat[];
  progress: Progress;
  unverified_refs: string[];
  bdu_version: string | null;
  snapshot: {
    refs: Record<string, { kind: string; title: string; revision: number; verified: boolean }>;
    bdu: Record<string, { title: string; changed_version: string | null }>;
    bdu_version: string | null;
  } | null;
}

export interface Candidate {
  code: string;
  title: string;
  source: string | null;
  target: string | null;
  conf: boolean | null;
  integ: boolean | null;
  avail: boolean | null;
  hint: Hint;
  category_match: boolean;
  in_model: boolean;
}

export const STATUS_LABELS: Record<ModelStatus, string> = {
  draft: "Черновик",
  approved: "Утверждена",
  superseded: "Заменена",
};

export const STATUS_PILL: Record<ModelStatus, string> = {
  draft: "pill-warn",
  approved: "pill-ok",
  superseded: "pill-muted",
};

/** Подсказки шагов: что Методика требует определить на шаге. */
export const STEP_HELP: Record<StepKey, string> = {
  consequences:
    "Какие негативные последствия возможны от нарушения безопасности информации в системе: ущерб физическим лицам (У1), юридическим лицам (У2), государству (У3).",
  objects:
    "Компоненты системы, воздействие на которые ведёт к выбранным последствиям, и виды воздействия на них.",
  intruders:
    "Какие виды нарушителей актуальны для системы и с какими возможностями (Н1–Н4). Каждое решение — с обоснованием.",
  methods: "Какими способами актуальные нарушители могут воздействовать на объекты и через какие интерфейсы.",
  scenarios: "Тактики (и техники) сценариев реализации угроз из приложения к Методике.",
  threats:
    "Угрозы из БДУ: актуальна угроза, если есть актуальный нарушитель, объект воздействия, способ, сценарий и негативное последствие.",
};

export const LINK_TITLES: Record<LinkKey, string> = {
  intruders: "Нарушители",
  objects: "Объекты воздействия",
  consequences: "Негативные последствия",
  methods: "Способы реализации",
  tactics: "Тактики сценария",
};

/** Свободный ключ нового объекта воздействия: o1, o2, … */
export function nextObjectKey(items: ImpactObject[]): string {
  const used = new Set(items.map((i) => i.key));
  let n = items.length + 1;
  while (used.has(`o${n}`)) n += 1;
  return `o${n}`;
}

/** Нарушение свойств безопасности угрозой БДУ: «К, Ц, Д». */
export function ciaText(t: { conf: boolean | null; integ: boolean | null; avail: boolean | null }): string {
  const out = [t.conf && "К", t.integ && "Ц", t.avail && "Д"].filter(Boolean);
  return out.length ? out.join(", ") : "—";
}

/**
 * Предложение связей для угрозы, которую признают актуальной: нарушители той же
 * категории (внешний/внутренний), что в БДУ, и всё выбранное на шагах 1, 2, 4, 5.
 * Методист затем снимает лишнее.
 */
export function suggestLinks(
  t: ModelThreat,
  steps: Steps,
  categoryOf: (code: string) => string | undefined,
): Record<LinkKey, string[]> {
  const actual = steps.intruders.items.filter((i) => i.relevant).map((i) => i.code);
  const byCat = actual.filter((c) => {
    const cat = categoryOf(c);
    return !t.hint.categories.length || (cat !== undefined && t.hint.categories.includes(cat));
  });
  return {
    intruders: byCat.length ? byCat : actual,
    objects: steps.objects.items.map((o) => o.key),
    consequences: steps.consequences.items.map((c) => c.code),
    methods: steps.methods.items.map((m) => m.code),
    tactics: steps.scenarios.items.map((s) => s.tactic),
  };
}
