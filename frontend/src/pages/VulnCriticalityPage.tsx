import { Calculator, CheckCheck, ExternalLink, FileText, Pencil, RotateCcw } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { VerifyBadge } from "../components/VerifyBadge";
import { apiGet, apiSend } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ORIGIN_LABELS } from "../lib/classification";
import { formatDateTime } from "../lib/format";
import {
  deadlineText,
  decimal,
  emptyInputs,
  levelClass,
  sourceLine,
  type CalculateResult,
  type Definition,
  type Indicator,
  type IndicatorValue,
  type Inputs,
  type Methodology,
  type MethodologyBrief,
  type Outcome,
  type Source,
} from "../lib/vulnCriticality";

const GROUP_HEAD: Record<string, string> = {
  infr: "Данные для расчёта показателя I_infr",
  at: "Данные для расчёта показателя I_at",
  imp: "Данные для расчёта показателя I_imp",
};

/** Произведение «вес × значение» без ошибок float: 0,5 × 1,1 = 0,55. */
function product(weight: number, score: number): string {
  return decimal(Number((weight * score).toFixed(6)).toString());
}

export function VulnCriticalityPage() {
  const { can } = useAuth();
  const [list, setList] = useState<MethodologyBrief[] | null>(null);
  const [m, setM] = useState<Methodology | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editValue, setEditValue] = useState<{ indicator: Indicator; value: IndicatorValue } | null>(null);
  const [editSource, setEditSource] = useState(false);

  const load = useCallback(() => {
    setError(null);
    apiGet<MethodologyBrief[]>("/refs/vuln-criticality")
      .then((rows) => {
        setList(rows);
        if (rows[0]) return apiGet<Methodology>(`/refs/vuln-criticality/${rows[0].id}`).then(setM);
      })
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  async function verify() {
    if (!m) return;
    try {
      setM(await apiSend<Methodology>("POST", `/refs/vuln-criticality/${m.id}/verify`, { revision: m.revision }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось отметить сверку");
    }
  }

  const def = m?.definition;
  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            <Link to="/refs">Справочники</Link> / Критичность уязвимостей
          </div>
          <h1>Методика оценки критичности уязвимостей</h1>
        </div>
        <div className="actions">
          <Link to="/refs/documents" className="btn">
            <FileText size={15} /> Нормативные документы
          </Link>
        </div>
      </div>

      {error && <ErrorAlert message={error} onRetry={load} />}
      {list === null && !error && <Loading />}
      {list?.length === 0 && (
        <section className="card">
          <EmptyState
            icon={<Calculator size={21} />}
            title="Методика не загружена"
            text="Справочник загружается из reference/vuln-criticality при старте сервиса."
          />
        </section>
      )}

      {m && def && (
        <>
          <div className={`alert ${m.verified ? "alert-ok" : "alert-warn"}`}>
            <span className="alert-text">
              {m.verified ? (
                <>
                  Сверено методистом: {m.verified_by_name}, {formatDateTime(m.verified_at)}.
                </>
              ) : (
                <>Справочник не сверен методистом. Оценки по нему помечаются «требует сверки».</>
              )}{" "}
              {m.source.note}
            </span>
          </div>

          <div className="row-phi">
            <section className="card">
              <div className="card-head">
                <h2>{m.title}</h2>
                <VerifyBadge verified={m.verified} by={m.verified_by_name} at={m.verified_at} />
              </div>
              <dl className="props card-pad">
                <dt>Документ</dt>
                <dd>
                  {m.source.document ?? "—"}
                  {m.source.url && (
                    <>
                      {" "}
                      <a href={m.source.url} target="_blank" rel="noreferrer noopener">
                        Текст <ExternalLink size={12} />
                      </a>
                    </>
                  )}
                </dd>
                <dt>Формула</dt>
                <dd>
                  <span className="mono">{def.formula.text}</span>
                  <span className="cell-sub"> · {sourceLine(def.formula.source)}</span>
                </dd>
                <dt>I_cvss</dt>
                <dd>
                  Базовая оценка CVSS {def.cvss.version}, от {def.cvss.min} до {def.cvss.max}
                  <div className="cell-sub">{def.cvss.note}</div>
                </dd>
                <dt>Версия</dt>
                <dd>
                  {m.version} <span className="muted">· ревизия {m.revision}</span>
                </dd>
                <dt>Происхождение</dt>
                <dd>{ORIGIN_LABELS[m.origin] ?? m.origin}</dd>
              </dl>
              <div className="card-pad actions">
                {can("refs.manage") && (
                  <button type="button" className="btn" onClick={() => setEditSource(true)}>
                    <Pencil size={15} /> Источник и версия
                  </button>
                )}
                {can("refs.verify") && !m.verified && (
                  <button type="button" className="btn btn-primary" onClick={verify}>
                    <CheckCheck size={15} /> Сверено с текстом
                  </button>
                )}
              </div>
            </section>

            <section className="card">
              <div className="card-head">
                <h2>Примеры приложения</h2>
                <span className="count">{m.examples.length}</span>
              </div>
              <ul className="history card-pad">
                {m.examples.map((ex) => (
                  <li key={ex.code}>
                    <span className="cell-title">{ex.title}</span>
                    <span className="cell-sub">
                      V = {decimal(ex.outcome.v)} · <span className={levelClass(ex.outcome.level.code)}>{ex.outcome.level.title}</span>{" "}
                      {ex.reproduced ? (
                        <span className="pill pill-ok">Воспроизводится</span>
                      ) : (
                        <span className="pill pill-danger">Ожидалось {decimal(ex.expected.v)}</span>
                      )}
                    </span>
                  </li>
                ))}
              </ul>
              <div className="card-head">
                <h2>История правок</h2>
                <span className="count">{m.revisions.length}</span>
              </div>
              {m.revisions.length === 0 ? (
                <p className="card-pad muted">Справочник не менялся с загрузки.</p>
              ) : (
                <ul className="history card-pad">
                  {m.revisions.map((r) => (
                    <li key={r.revision}>
                      <span className="cell-title">
                        Ревизия {r.revision} → {r.revision + 1}
                      </span>
                      <span className="cell-sub">
                        {formatDateTime(r.changed_at)}, {r.changed_by_name ?? "—"}
                        {r.comment && ` · ${r.comment}`}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>

          <IndicatorsTable
            def={def}
            onEdit={can("refs.manage") ? (indicator, value) => setEditValue({ indicator, value }) : undefined}
          />
          <LevelsTable def={def} />
          <CalculatorCard methodology={m} />
          <MeasuresCard def={def} />
        </>
      )}

      {editValue && m && (
        <ValueDialog
          methodology={m}
          indicator={editValue.indicator}
          value={editValue.value}
          onClose={() => setEditValue(null)}
          onSaved={(x) => {
            setEditValue(null);
            setM(x);
          }}
        />
      )}
      {editSource && m && (
        <SourceDialog
          methodology={m}
          onClose={() => setEditSource(false)}
          onSaved={(x) => {
            setEditSource(false);
            setM(x);
          }}
        />
      )}
    </>
  );
}

function IndicatorsTable({
  def,
  onEdit,
}: {
  def: Definition;
  onEdit?: (i: Indicator, v: IndicatorValue) => void;
}) {
  return (
    <section className="card">
      <div className="card-head">
        <h2>Таблица 1. Весовые коэффициенты и значения показателей</h2>
      </div>
      <div className="table-wrap">
        <table className="table vc-table">
          <thead>
            <tr>
              <th>Показатель</th>
              <th className="num">Вес</th>
              <th>Значение показателя</th>
              <th className="num">Оценка</th>
              <th className="num">Итог</th>
            </tr>
          </thead>
          {def.groups.map((g) => (
            <tbody key={g.code}>
              <tr className="vc-group">
                <td colSpan={5}>
                  {GROUP_HEAD[g.code]} · <span className="mono">{g.formula}</span>
                  <span className="cell-sub"> · {sourceLine(g.source)}</span>
                </td>
              </tr>
              {def.indicators
                .filter((i) => i.group === g.code)
                .flatMap((ind) =>
                  ind.values.map((v, idx) => (
                    <tr
                      key={v.code}
                      className={onEdit ? "clickable" : undefined}
                      onClick={onEdit ? () => onEdit(ind, v) : undefined}
                    >
                      {idx === 0 && (
                        <td rowSpan={ind.values.length} className="vc-ind">
                          <span className="cell-title">
                            {ind.title} ({ind.code})
                          </span>
                          <div className="cell-sub">
                            {sourceLine(ind.source)}
                            {ind.multiple === "max" && " · несколько значений — наибольшее"}
                          </div>
                          {ind.source?.note && <div className="cell-sub">{ind.source.note}</div>}
                        </td>
                      )}
                      {idx === 0 && (
                        <td rowSpan={ind.values.length} className="num nowrap">
                          {ind.weight_symbol} = {decimal(ind.weight)}
                        </td>
                      )}
                      <td>
                        <span className="tag">{v.code}</span> {v.title}
                      </td>
                      <td className="num">{decimal(v.score)}</td>
                      <td className="num">{product(ind.weight, v.score)}</td>
                    </tr>
                  )),
                )}
            </tbody>
          ))}
        </table>
      </div>
    </section>
  );
}

function LevelsTable({ def }: { def: Definition }) {
  return (
    <section className="card">
      <div className="card-head">
        <h2>Таблица 2. Уровни критичности и сроки устранения</h2>
        <span className="cell-sub">п. 18, 21</span>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Уровень</th>
              <th>Итоговая оценка</th>
              <th>Рекомендуемый срок устранения</th>
            </tr>
          </thead>
          <tbody>
            {def.levels.map((lv) => (
              <tr key={lv.code}>
                <td>
                  <span className={levelClass(lv.code)}>{lv.title}</span>
                </td>
                <td className="nowrap mono">{lv.condition}</td>
                <td>
                  <span className="cell-title">{deadlineText(lv.deadline)}</span>
                  {lv.deadline.text && <div className="cell-sub">{lv.deadline.text}</div>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {def.rounding?.note && (
        <p className="card-pad cell-sub">
          V округляется до {def.rounding.digits} знаков; уровень — по округлённому значению. {def.rounding.note}
        </p>
      )}
    </section>
  );
}

function CalculatorCard({ methodology }: { methodology: Methodology }) {
  const def = methodology.definition;
  const [inputs, setInputs] = useState<Inputs>(() => emptyInputs(def));
  const [result, setResult] = useState<CalculateResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const pick = (ind: Indicator, code: string) =>
    setInputs((prev) => {
      const cur = (prev[ind.code] as string[]) ?? [];
      const next =
        ind.multiple === "max"
          ? cur.includes(code)
            ? cur.filter((c) => c !== code)
            : [...cur, code]
          : [code];
      return { ...prev, [ind.code]: next };
    });

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      setResult(
        await apiSend<CalculateResult>("POST", `/refs/vuln-criticality/${methodology.id}/calculate`, { inputs }),
      );
    } catch (err) {
      setResult(null);
      setError(err instanceof Error ? err.message : "Не удалось рассчитать");
    }
  }

  return (
    <section className="card">
      <div className="card-head">
        <h2>Расчёт по Методике</h2>
        <div className="actions">
          {(def.examples ?? []).map((ex, n) => (
            <button
              key={ex.code}
              type="button"
              className="btn btn-sm"
              title={ex.title}
              onClick={() => {
                setInputs({ ...emptyInputs(def), ...ex.inputs });
                setResult(null);
              }}
            >
              Пример {n + 1}
            </button>
          ))}
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => {
              setInputs(emptyInputs(def));
              setResult(null);
              setError(null);
            }}
          >
            <RotateCcw size={14} /> Сбросить
          </button>
        </div>
      </div>
      <form className="card-pad form-stack" onSubmit={submit}>
        <p className="cell-sub">
          Проверка справочника: расчёт по текущей ревизии, ничего не сохраняется. Оценки уязвимостей объекта
          появятся в карточке объекта.
        </p>
        <label className="field vc-cvss">
          <span>I_cvss — базовая оценка CVSS {def.cvss.version}</span>
          <input
            className="input"
            inputMode="decimal"
            value={String(inputs.cvss ?? "")}
            placeholder="например, 8,8"
            onChange={(e) => setInputs((p) => ({ ...p, cvss: e.target.value }))}
          />
        </label>
        {def.indicators.map((ind) => {
          const cur = (inputs[ind.code] as string[]) ?? [];
          return (
            <fieldset key={ind.code} className="field">
              <span>
                {ind.code} — {ind.title}
                {ind.multiple === "max" && <small> · можно несколько, берётся наибольшее</small>}
              </span>
              <div className="chips">
                {ind.values.map((v) => (
                  <button
                    key={v.code}
                    type="button"
                    className="chip"
                    aria-pressed={cur.includes(v.code)}
                    title={v.title}
                    onClick={() => pick(ind, v.code)}
                  >
                    {v.code} · {decimal(v.score)}
                  </button>
                ))}
              </div>
              {cur.length > 0 && (
                <small>{ind.values.filter((v) => cur.includes(v.code)).map((v) => v.title).join("; ")}</small>
              )}
            </fieldset>
          );
        })}
        {def.certified_szi && (
          <label className="check">
            <input
              type="checkbox"
              checked={Boolean(inputs.certified_szi)}
              onChange={(e) => setInputs((p) => ({ ...p, certified_szi: e.target.checked }))}
            />
            <span>
              <b>Уязвимость в сертифицированном СЗИ</b>
              <small>п. {def.certified_szi.source?.clause}: присваивается критический уровень</small>
            </span>
          </label>
        )}
        {error && <ErrorAlert message={error} />}
        <div>
          <button type="submit" className="btn btn-primary">
            <Calculator size={15} /> Рассчитать
          </button>
        </div>
      </form>
      {result && <OutcomeView outcome={result.outcome} />}
    </section>
  );
}

function OutcomeView({ outcome }: { outcome: Outcome }) {
  const g = outcome.groups;
  return (
    <div className="card-pad vc-outcome" aria-label="Результат расчёта">
      <div className="kpi-row">
        <div className="kpi">
          <div className="kpi-label">V</div>
          <div className="kpi-value">{decimal(outcome.v)}</div>
          <div className="cell-sub">точно {decimal(outcome.v_exact)}</div>
        </div>
        <div className="kpi">
          <div className="kpi-label">Уровень</div>
          <div className="kpi-value">
            <span className={levelClass(outcome.level.code)}>{outcome.level.title}</span>
          </div>
          <div className="cell-sub">{outcome.level.condition}</div>
        </div>
        <div className="kpi">
          <div className="kpi-label">Срок устранения</div>
          <div className="kpi-value">{deadlineText(outcome.level.deadline)}</div>
          <div className="cell-sub">п. 21</div>
        </div>
      </div>
      <p className="mono vc-formula">
        V = {decimal(outcome.cvss)} × {decimal(g.infr)} × ({decimal(g.at)} + {decimal(g.imp)}) ≈ {decimal(outcome.v)}
      </p>
      {outcome.level_by_v && (
        <div className="alert alert-warn">
          <span className="alert-text">
            По значению V уровень был бы другим; критический присвоен по п. 4 — уязвимость в сертифицированном СЗИ.
          </span>
        </div>
      )}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Показатель</th>
              <th>Значение</th>
              <th className="num">Вес × оценка</th>
              <th>Источник</th>
            </tr>
          </thead>
          <tbody>
            {outcome.trace.map((t) => (
              <tr key={t.indicator}>
                <td className="nowrap">{t.indicator === "cvss" ? "I_cvss" : t.indicator}</td>
                <td>
                  {t.value ? (
                    <>
                      <span className="tag">{t.value}</span> {t.value_title}
                      {t.rule && (
                        <div className="cell-sub">
                          {t.rule} из {t.chosen?.map((c) => `${c.code} (${decimal(c.score)})`).join(", ")}
                        </div>
                      )}
                    </>
                  ) : (
                    t.title
                  )}
                </td>
                <td className="num nowrap">
                  {t.weight ? `${decimal(t.weight)} × ${decimal(t.score)} = ${decimal(t.product)}` : decimal(t.score)}
                </td>
                <td className="cell-sub">{sourceLine(t.source)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function MeasuresCard({ def }: { def: Definition }) {
  return (
    <section className="card">
      <div className="card-head">
        <h2>Устранение уязвимостей и компенсирующие меры</h2>
        <span className="cell-sub">п. 4, 22–25</span>
      </div>
      <div className="card-pad form-stack">
        {def.certified_szi && (
          <div className="alert alert-info">
            <span className="alert-text">
              <b>П. {def.certified_szi.source?.clause}.</b> {def.certified_szi.text}
            </span>
          </div>
        )}
        {def.remediation && <p>{def.remediation.text}</p>}
        {def.compensating_measures && (
          <>
            <h3>Компенсирующие меры (п. {def.compensating_measures.source?.clause})</h3>
            <ol className="vc-list">
              {def.compensating_measures.items.map((c) => (
                <li key={c.code}>{c.title}</li>
              ))}
            </ol>
          </>
        )}
        {def.recalculation && (
          <>
            <h3>Когда расчёт повторяется</h3>
            <ul className="vc-list">
              {def.recalculation.map((r) => (
                <li key={r.text}>
                  {r.text} <span className="cell-sub">· п. {r.source?.clause}</span>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
    </section>
  );
}

function ValueDialog({
  methodology,
  indicator,
  value,
  onClose,
  onSaved,
}: {
  methodology: Methodology;
  indicator: Indicator;
  value: IndicatorValue;
  onClose: () => void;
  onSaved: (m: Methodology) => void;
}) {
  const [title, setTitle] = useState(value.title);
  const [score, setScore] = useState(decimal(value.score));
  const [weight, setWeight] = useState(decimal(indicator.weight));
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const s = Number(score.replace(",", "."));
    const w = Number(weight.replace(",", "."));
    if (!Number.isFinite(s) || !Number.isFinite(w)) {
      setError("Оценка и вес — числа");
      return;
    }
    setBusy(true);
    setError(null);
    const next: Definition = structuredClone(methodology.definition);
    const ind = next.indicators.find((i) => i.code === indicator.code);
    const val = ind?.values.find((v) => v.code === value.code);
    if (!ind || !val) return;
    ind.weight = w;
    val.score = s;
    val.title = title.trim();
    try {
      onSaved(
        await apiSend<Methodology>("PATCH", `/refs/vuln-criticality/${methodology.id}`, {
          definition: next,
          comment: comment.trim(),
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось сохранить");
      setBusy(false);
    }
  }

  return (
    <Modal
      title={`Значение ${value.code}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="vc-value" className="btn btn-primary" disabled={busy || !comment.trim() || !title.trim()}>
            Сохранить
          </button>
        </>
      }
    >
      <form id="vc-value" className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <div className="field">
          <span>Показатель</span>
          <div>
            {indicator.title} ({indicator.code}) · {sourceLine(indicator.source)}
          </div>
        </div>
        <label className="field">
          <span>Наименование значения</span>
          <textarea className="textarea" rows={2} value={title} onChange={(e) => setTitle(e.target.value)} />
          <small>Дословно из таблицы 1</small>
        </label>
        <div className="form-row">
          <label className="field">
            <span>Оценка ({indicator.code})</span>
            <input className="input" inputMode="decimal" value={score} onChange={(e) => setScore(e.target.value)} />
          </label>
          <label className="field">
            <span>Весовой коэффициент ({indicator.weight_symbol})</span>
            <input className="input" inputMode="decimal" value={weight} onChange={(e) => setWeight(e.target.value)} />
          </label>
        </div>
        <label className="field">
          <span>Основание правки</span>
          <input
            className="input"
            value={comment}
            maxLength={1000}
            required
            placeholder="Например: сверено с таблицей 1"
            onChange={(e) => setComment(e.target.value)}
          />
          <small>
            Правка создаёт новую ревизию и снимает отметку о сверке. Если примеры приложения перестанут
            воспроизводиться, правка не сохранится.
          </small>
        </label>
      </form>
    </Modal>
  );
}

function SourceDialog({
  methodology,
  onClose,
  onSaved,
}: {
  methodology: Methodology;
  onClose: () => void;
  onSaved: (m: Methodology) => void;
}) {
  const [src, setSrc] = useState<Source>({ ...methodology.source });
  const [version, setVersion] = useState(methodology.version);
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof Source, v: string) => setSrc((p) => ({ ...p, [k]: v }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const clean = Object.fromEntries(
      (["document", "clause", "appendix", "url", "note"] as const).map((k) => {
        const v = src[k];
        return [k, typeof v === "string" && v.trim() ? v.trim() : null];
      }),
    );
    try {
      onSaved(
        await apiSend<Methodology>("PATCH", `/refs/vuln-criticality/${methodology.id}`, {
          source: clean,
          version: version.trim(),
          comment: comment.trim(),
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось сохранить");
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Источник справочника"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="submit"
            form="vc-source"
            className="btn btn-primary"
            disabled={busy || !comment.trim() || !src.document?.trim() || !version.trim()}
          >
            Сохранить
          </button>
        </>
      }
    >
      <form id="vc-source" className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <label className="field">
          <span>Документ</span>
          <input className="input" value={src.document ?? ""} required onChange={(e) => set("document", e.target.value)} />
        </label>
        <label className="field">
          <span>Ссылка</span>
          <input className="input" value={src.url ?? ""} onChange={(e) => set("url", e.target.value)} />
        </label>
        <label className="field">
          <span>Примечание</span>
          <textarea className="textarea" rows={2} value={src.note ?? ""} onChange={(e) => set("note", e.target.value)} />
        </label>
        <label className="field">
          <span>Версия справочника</span>
          <input className="input" value={version} maxLength={64} onChange={(e) => setVersion(e.target.value)} />
        </label>
        <label className="field">
          <span>Основание правки</span>
          <input className="input" value={comment} maxLength={1000} required onChange={(e) => setComment(e.target.value)} />
        </label>
      </form>
    </Modal>
  );
}
