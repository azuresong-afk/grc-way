import { CheckCircle2, ExternalLink, Pencil } from "lucide-react";
import {
  describeWhen,
  fieldLabel,
  sourceText,
  valueLabel,
  type Definition,
  type Source,
  type TraceStep,
} from "../lib/classification";

/** Как получен результат: для каждого шага — строки таблицы, сработавшая выделена, с источником. */
export function ClassTrace({
  definition,
  trace,
  inputs,
  tableSource,
  onRow,
}: {
  definition: Definition;
  trace: TraceStep[];
  inputs: Record<string, string>;
  tableSource: Source;
  // Справочник: клик по строке открывает правку.
  onRow?: (stepKey: string, rowId: string) => void;
}) {
  return (
    <div className="trace">
      {definition.steps.map((step, i) => {
        const t = trace.find((x) => x.key === step.key);
        return (
          <div key={step.key} className="trace-step">
            <div className="trace-head">
              <span className="trace-num">{i + 1}</span>
              <b>{step.label}</b>
              {t && (
                <span className="pill pill-info">
                  {valueLabel(definition, step.key, t.value)}
                </span>
              )}
            </div>
            {step.method === "first_match" ? (
              <div className="table-wrap">
                <table className="table table-compact">
                  <thead>
                    <tr>
                      <th>Условие</th>
                      <th>Значение</th>
                      <th>Источник</th>
                      {onRow && <th className="cell-actions" aria-label="Действия" />}
                    </tr>
                  </thead>
                  <tbody>
                    {step.rows?.map((r) => {
                      const hit = t?.row_id === r.id;
                      const src = { ...tableSource, ...(r.source ?? step.source ?? {}) };
                      return (
                        <tr
                          key={r.id}
                          className={[hit && "selected", onRow && "clickable"].filter(Boolean).join(" ") || undefined}
                          aria-current={hit || undefined}
                          onClick={onRow ? () => onRow(step.key, r.id) : undefined}
                        >
                          <td>
                            {Object.keys(r.when).length === 0 ? (
                              <span className="muted">иначе</span>
                            ) : (
                              describeWhen(definition, r.when).map((w) => <div key={w}>{w}</div>)
                            )}
                            {r.note && <div className="cell-sub">{r.note}</div>}
                          </td>
                          <td className="nowrap">
                            {hit && <CheckCircle2 size={14} className="trace-hit" aria-label="Сработала" />}{" "}
                            <b>{r.value}</b>
                          </td>
                          <td className="cell-sub">{sourceText(src) || "—"}</td>
                          {onRow && (
                            <td className="cell-actions">
                              <button
                                type="button"
                                className="icon-btn"
                                aria-label={`Изменить строку ${r.id}`}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onRow(step.key, r.id);
                                }}
                              >
                                <Pencil size={14} />
                              </button>
                            </td>
                          )}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="card-pad trace-max">
                <p className="muted">
                  Наиболее строгое значение среди показателей (порядок: {step.order?.map((v) => valueLabel(definition, step.key, v)).join(" → ")}).{" "}
                  {sourceText({ ...tableSource, ...(step.source ?? {}) })}
                </p>
                <ul className="history">
                  {step.fields?.map((f) => {
                    const hit = t ? f in t.matched : false;
                    return (
                      <li key={f} className={hit ? "trace-max-hit" : undefined}>
                        {hit && <CheckCircle2 size={14} className="trace-hit" aria-label="Определило итог" />}{" "}
                        {fieldLabel(definition, f)}
                        {inputs[f] && (
                          <span className="cell-sub"> · {valueLabel(definition, f, inputs[f])}</span>
                        )}
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}
          </div>
        );
      })}
      {tableSource.url && (
        <p className="cell-sub">
          <a href={tableSource.url} target="_blank" rel="noreferrer noopener">
            Текст документа <ExternalLink size={12} />
          </a>
        </p>
      )}
    </div>
  );
}
