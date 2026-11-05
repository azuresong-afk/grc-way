// Инвентаризация объекта для показателя I_infr (Методика 2025, задача 2.7):
// тип компонента и доступность из сети «Интернет» у хостов, проверка K, L, P.

import { AlertTriangle, Calculator, CheckCircle2 } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { apiGet, apiSend } from "../lib/api";
import type { ComponentType, InfrResult, Inventory } from "../lib/objects";

let typesCache: Promise<ComponentType[]> | null = null;

/** Типы компонента из справочника Методики (значения показателя K). */
export function useComponentTypes(): ComponentType[] | null {
  const [types, setTypes] = useState<ComponentType[] | null>(null);
  useEffect(() => {
    let alive = true;
    typesCache ??= apiGet<ComponentType[]>("/refs/component-types").catch((e) => {
      typesCache = null;
      throw e;
    });
    typesCache.then(
      (t) => alive && setTypes(t),
      () => alive && setTypes([]),
    );
    return () => {
      alive = false;
    };
  }, []);
  return types;
}

export function TypeChips({ codes, types }: { codes: string[] | null; types: ComponentType[] | null }) {
  if (!codes?.length) return <span className="pill pill-warn">не указан</span>;
  const by = new Map((types ?? []).map((t) => [t.code, t]));
  return (
    <div className="type-chips">
      {codes.map((c) => (
        <span key={c} className="type-chip" title={by.get(c)?.title}>
          {by.get(c)?.short ?? c}
        </span>
      ))}
    </div>
  );
}

/** Выбор одного или нескольких типов: при нескольких в расчёте берётся наибольшее (п. 15). */
export function TypePicker({
  types,
  value,
  onChange,
}: {
  types: ComponentType[];
  value: string[];
  onChange: (v: string[]) => void;
}) {
  function toggle(code: string, on: boolean) {
    const next = on ? [...value, code] : value.filter((c) => c !== code);
    onChange(types.map((t) => t.code).filter((c) => next.includes(c)));
  }
  return (
    <div className="option-grid type-grid">
      {types.map((t) => {
        const on = value.includes(t.code);
        return (
          <label key={t.code} className={`check option${on ? " checked" : ""}`}>
            <input type="checkbox" checked={on} onChange={(e) => toggle(t.code, e.target.checked)} />
            <span>
              <b>{t.short}</b>
              <small>{t.title}</small>
            </span>
          </label>
        );
      })}
    </div>
  );
}

export function InventoryCard({ inventory, onShowGaps }: { inventory: Inventory | null; onShowGaps: () => void }) {
  if (!inventory) return null;
  const gaps = new Set([...inventory.missing_type, ...inventory.missing_internet]).size;
  const filled = inventory.hosts_total - gaps;
  const used = inventory.types.filter((t) => t.total > 0);
  return (
    <section className="card">
      <div className="card-head">
        <h2>Инвентаризация для оценки уязвимостей</h2>
        <Link className="btn btn-sm btn-ghost" to="/refs/vuln-criticality">
          Методика 2025, таблица 1
        </Link>
      </div>
      <div className="card-pad inv-summary">
        {inventory.hosts_total === 0 ? (
          <span className="muted">Хостов нет — добавьте состав, затем укажите тип и доступность.</span>
        ) : inventory.ready ? (
          <span className="inv-state inv-ok">
            <CheckCircle2 size={16} /> Тип компонента и доступность из «Интернета» указаны у всех{" "}
            {inventory.hosts_total} хостов
          </span>
        ) : (
          <span className="inv-state inv-warn">
            <AlertTriangle size={16} /> Заполнено у {filled} из {inventory.hosts_total} хостов: без типа{" "}
            {inventory.missing_type.length}, без признака доступности {inventory.missing_internet.length}
            <button type="button" className="link-btn" onClick={onShowGaps}>
              Показать
            </button>
          </span>
        )}
        <small className="muted">
          Тип и доступность нужны для показателей K, L и P (п. 14): L — доля уязвимых хостов каждого типа от всех хостов
          этого типа в объекте.
        </small>
      </div>
      {inventory.internet_conflict.length > 0 && (
        <div className="card-pad">
          <div className="alert alert-warn">
            <AlertTriangle size={15} />
            <span className="alert-text">
              Доступны из «Интернета» хосты {inventory.internet_conflict.join(", ")}, а в описании объекта подключения к
              сети «Интернет» нет. Проверьте описание или признак у хостов.
            </span>
          </div>
        </div>
      )}
      {used.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Тип компонента</th>
                <th className="num">K</th>
                <th className="num">Хостов</th>
                <th className="num">Доступны из «Интернета»</th>
              </tr>
            </thead>
            <tbody>
              {used.map((t) => (
                <tr key={t.code}>
                  <td>
                    <div className="cell-title">{t.short}</div>
                    <div className="cell-sub">{t.title}</div>
                  </td>
                  <td className="num mono">{String(t.score).replace(".", ",")}</td>
                  <td className="num">{t.total}</td>
                  <td className="num">{t.internet}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export function BulkTypeDialog({
  count,
  types,
  onClose,
  onApply,
}: {
  count: number;
  types: ComponentType[];
  onClose: () => void;
  onApply: (codes: string[]) => Promise<boolean>;
}) {
  const [value, setValue] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  return (
    <Modal
      title={`Тип компонента: ${count} ${count === 1 ? "хост" : "хостов"}`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={busy || value.length === 0}
            onClick={async () => {
              setBusy(true);
              if (!(await onApply(value))) setBusy(false);
            }}
          >
            Задать
          </button>
        </>
      }
    >
      <p className="muted small">
        Тип заменит указанный у выбранных хостов. Если хост относится к нескольким типам (например, сервер,
        обеспечивающий важные процессы), отметьте все — в расчёте берётся наибольшее значение (п. 15).
      </p>
      <TypePicker types={types} value={value} onChange={setValue} />
    </Modal>
  );
}

/** «50-70% компонентов от общего числа…» → «50–70 %». */
function bandShort(title: string): string {
  return title
    .replace(/\s*компонентов.*$/, "")
    .replace(/(\d)-(\d)/, "$1–$2")
    .replace(/(\d)%/, "$1 %");
}

function num(s: string | null | undefined): string {
  return (s ?? "").replace(".", ",");
}

export function InfrDialog({
  objectId,
  addresses,
  onClose,
}: {
  objectId: string;
  addresses: string[];
  onClose: () => void;
}) {
  const [result, setResult] = useState<InfrResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiSend<InfrResult>("POST", `/objects/${objectId}/inventory/infr`, {
      addresses,
    }).then(setResult, (e: Error) => setError(e.message));
  }, [objectId, addresses]);

  return (
    <Modal
      title="Проверка I_infr по составу объекта"
      onClose={onClose}
      footer={
        <button type="button" className="btn" onClick={onClose}>
          Закрыть
        </button>
      }
    >
      {error && <ErrorAlert message={error} />}
      {!result && !error && <Loading />}
      {result && (
        <div className="form-stack">
          <p className="muted small">
            Уязвимыми считаются выбранные хосты ({addresses.length}). Ничего не сохраняется: реестр уязвимостей объекта
            с оценкой V появится в задаче 2.8. Методика {result.methodology.version}, ревизия{" "}
            {result.methodology.revision}
            {!result.methodology.verified && " (не сверена методистом)"}.
          </p>
          {result.complete ? (
            <div className="inv-result">
              <span className="inv-result-label">
                <Calculator size={16} /> I<sub>infr</sub> =
              </span>
              <span className="inv-result-value mono">{num(result.i_infr)}</span>
              <span className="muted">
                = {result.trace.map((r) => `${num(r.weight)} × ${num(r.score)}`).join(" + ")}
              </span>
            </div>
          ) : (
            <div className="alert alert-warn">
              <AlertTriangle size={15} />
              <div className="alert-text">
                <b>Не хватает данных инвентаризации — I_infr не считается.</b>
                <ul className="plain-list">
                  {result.missing.map((m) => (
                    <li key={m.indicator}>
                      {m.indicator}: {m.text}
                      {m.addresses.length > 0 && (
                        <>
                          {" "}
                          — <span className="mono">{m.addresses.slice(0, 8).join(", ")}</span>
                          {m.addresses.length > 8 && ` и ещё ${m.addresses.length - 8}`}
                        </>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {result.by_type.length > 0 && (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Тип уязвимых хостов (K)</th>
                    <th className="num">Уязвимы</th>
                    <th className="num">Доля</th>
                    <th>Полоса L</th>
                  </tr>
                </thead>
                <tbody>
                  {result.by_type.map((r) => (
                    <tr key={r.code}>
                      <td>{r.short}</td>
                      <td className="num nowrap">
                        {r.vulnerable} из {r.total}
                      </td>
                      <td className="num mono nowrap">{num(r.share)} %</td>
                      <td className="nowrap">
                        {r.band_title ? (
                          <span title={r.band_title}>{bandShort(r.band_title)}</span>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {result.trace.length > 0 && (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Показатель</th>
                    <th>Значение</th>
                    <th className="num">Вес × оценка</th>
                  </tr>
                </thead>
                <tbody>
                  {result.trace.map((r) => (
                    <tr key={r.indicator}>
                      <td>
                        <div className="cell-title">{r.indicator}</div>
                        <div className="cell-sub">{r.title}</div>
                      </td>
                      <td>
                        {r.value_title}
                        {r.rule && <div className="cell-sub">{r.rule}</div>}
                      </td>
                      <td className="num mono nowrap">
                        {num(r.weight)} × {num(r.score)} = {num(r.product)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
