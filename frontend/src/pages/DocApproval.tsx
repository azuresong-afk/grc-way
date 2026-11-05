// Согласование документов и сравнение версий (задача 3.3).
import { ArrowRight, Check, GitCompare, Send, Undo2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Drawer } from "../components/Drawer";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { ApiError, apiGet, apiSend } from "../lib/api";
import { formatDateTime, formatNumber } from "../lib/format";
import {
  REVIEW_TITLES,
  STATE_PILL,
  STATUS_PILL,
  type DocBrief,
  type DocCompare,
  type DocFull,
  type DocReview,
} from "../lib/objectDocs";

function message(e: unknown, fallback: string): string {
  return e instanceof ApiError || e instanceof Error ? e.message : fallback;
}

export function StatusPill({ d }: { d: Pick<DocBrief, "status" | "status_title"> }) {
  return <span className={`pill ${STATUS_PILL[d.status]}`}>{d.status_title}</span>;
}

/** Кто и когда утвердил / отправил — строка под статусом. */
export function statusNote(d: DocBrief): string | null {
  if ((d.status === "approved" || d.status === "superseded") && d.approved_at)
    return `${formatDateTime(d.approved_at)} · ${d.approved_by_name ?? "—"}`;
  if (d.status === "review" && d.submitted_at)
    return `с ${formatDateTime(d.submitted_at)} · ${d.submitted_by_name ?? "—"}`;
  return null;
}

export function ReviewHistory({ items }: { items: DocReview[] }) {
  if (items.length === 0) return <p className="muted">Версия ещё не отправлялась на согласование.</p>;
  return (
    <ol className="review-log">
      {items.map((r, i) => (
        <li key={i} className={`review-${r.action}`}>
          <span className="review-dot" aria-hidden="true" />
          <div>
            <span className="cell-title">{REVIEW_TITLES[r.action]}</span>
            <div className="cell-sub">
              {formatDateTime(r.at)} · {r.actor_name ?? "система"}
            </div>
            {r.comment && <div className="review-comment">{r.comment}</div>}
          </div>
        </li>
      ))}
    </ol>
  );
}

export type ReviewKind = "submit" | "return" | "approve";

const KIND: Record<ReviewKind, { title: string; button: string; label: string; required: boolean }> = {
  submit: {
    title: "Отправить на согласование",
    button: "Отправить",
    label: "Комментарий для утверждающего",
    required: false,
  },
  return: {
    title: "Вернуть в проект",
    button: "Вернуть",
    label: "Что доработать",
    required: true,
  },
  approve: {
    title: "Утвердить документ",
    button: "Утвердить",
    label: "Комментарий",
    required: false,
  },
};

/** Подтверждение шага согласования: комментарий, для несверенных записей — отметка. */
export function ReviewModal({
  doc,
  kind,
  onClose,
  onDone,
}: {
  doc: DocFull;
  kind: ReviewKind;
  onClose: () => void;
  onDone: (d: DocFull) => void;
}) {
  const k = KIND[kind];
  const [comment, setComment] = useState("");
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const needsAck = kind === "approve" && doc.unverified.length > 0;
  const ready = (!k.required || comment.trim() !== "") && (!needsAck || ack);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      const body =
        kind === "approve"
          ? { comment: comment.trim() || null, acknowledge_unverified: ack }
          : { comment: comment.trim() || (kind === "return" ? "" : null) };
      onDone(await apiSend<DocFull>("POST", `/documents/${doc.id}/${kind}`, body));
    } catch (e) {
      setError(message(e, "Не удалось выполнить действие"));
      setBusy(false);
    }
  }

  return (
    <Modal
      title={`${k.title}: v${doc.version}`}
      onClose={onClose}
      footer={
        <>
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="button"
            className={`btn ${kind === "return" ? "" : "btn-primary"}`}
            disabled={!ready || busy}
            onClick={() => void run()}
          >
            {busy ? "Сохраняем…" : k.button}
          </button>
        </>
      }
    >
      <p className="muted">
        {kind === "submit" &&
          "Версия уйдёт утверждающему. Пока она на согласовании, новая версия вернёт её в проект: согласуется только последняя."}
        {kind === "return" && "Версия вернётся в проект; причина попадёт в историю согласования."}
        {kind === "approve" &&
          "Документ пересоберётся без отметки «Проект» с датой утверждения и вашим именем на титуле; прежняя утверждённая версия станет «Заменён». Наблюдатель увидит документ."}
      </p>
      <label className="field">
        <span>
          {k.label}
          {k.required ? "" : " (необязательно)"}
        </span>
        <textarea
          className="input"
          rows={3}
          maxLength={2000}
          value={comment}
          onChange={(e) => setComment(e.target.value)}
        />
      </label>
      {needsAck && (
        <label className="check">
          <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
          <span>
            <b>Утверждаю с несверенными записями справочников</b>
            <small>
              {doc.unverified.map((u) => u.title).join("; ")}. Водяной знак «Проект» останется, пока методист не сверит
              эти записи и документ не будет сформирован заново.
            </small>
          </span>
        </label>
      )}
      {error && <ErrorAlert message={error} />}
    </Modal>
  );
}

/** Кнопки шага согласования в подвале шторки версии. */
export function ReviewButtons({ doc, onPick }: { doc: DocFull; onPick: (k: ReviewKind) => void }) {
  const a = doc.actions;
  return (
    <>
      {a.send_back && (
        <button type="button" className="btn btn-sm" onClick={() => onPick("return")}>
          <Undo2 size={14} /> Вернуть в проект
        </button>
      )}
      {a.submit && (
        <button type="button" className="btn btn-primary btn-sm" onClick={() => onPick("submit")}>
          <Send size={14} /> На согласование
        </button>
      )}
      {doc.status === "review" && (a.approve || a.approve_blocker) && (
        <button
          type="button"
          className="btn btn-primary btn-sm"
          disabled={!a.approve}
          title={a.approve_blocker ?? undefined}
          onClick={() => onPick("approve")}
        >
          <Check size={14} /> Утвердить
        </button>
      )}
    </>
  );
}

function Pair({ before, after }: { before: string | null; after: string | null }) {
  return (
    <span className="diff-text">
      {before ? <del className="diff-del">{before}</del> : <span className="muted">—</span>}
      <ArrowRight size={12} className="muted" aria-hidden="true" />
      {after ? <ins className="diff-ins">{after}</ins> : <span className="muted">—</span>}
    </span>
  );
}

/** Сравнение двух версий документа: сведения, поля, текст. */
export function CompareDrawer({
  versions,
  initial,
  onClose,
}: {
  versions: DocBrief[];
  initial: [string, string];
  onClose: () => void;
}) {
  const [pair, setPair] = useState<[string, string]>(initial);
  const [data, setData] = useState<DocCompare | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [onlyChanges, setOnlyChanges] = useState(true);

  useEffect(() => {
    if (pair[0] === pair[1]) return;
    let alive = true;
    setData(null);
    setError(null);
    apiGet<DocCompare>(`/documents/${pair[1]}/compare?with=${pair[0]}`)
      .then((d) => alive && setData(d))
      .catch((e: Error) => alive && setError(e.message));
    return () => {
      alive = false;
    };
  }, [pair]);

  const title = versions[0]?.title ?? "Документ";
  const lines = useMemo(() => data?.hunks ?? [], [data]);

  function pick(i: 0 | 1, id: string) {
    setPair((p) => (i === 0 ? [id, p[1]] : [p[0], id]));
  }

  return (
    <Drawer
      wide
      title={
        <>
          <GitCompare size={16} className="doc-icon" /> Сравнение версий
        </>
      }
      subtitle={title}
      onClose={onClose}
    >
      <section className="drawer-section">
        <div className="compare-pick">
          {(["Было", "Стало"] as const).map((label, i) => (
            <label key={label} className="field">
              <span>{label}</span>
              <select className="input" value={pair[i]} onChange={(e) => pick(i as 0 | 1, e.target.value)}>
                {versions.map((v) => (
                  <option key={v.id} value={v.id}>
                    v{v.version} · {v.status_title} · {formatDateTime(v.created_at)}
                  </option>
                ))}
              </select>
            </label>
          ))}
        </div>
        {pair[0] === pair[1] && <p className="muted">Выберите две разные версии.</p>}
      </section>
      {error && <ErrorAlert message={error} />}
      {!data && !error && pair[0] !== pair[1] && <Loading />}
      {data && (
        <>
          <section className="drawer-section">
            <div className="compare-sum">
              <span>
                <span className="mono">v{data.old.version}</span> <StatusPill d={data.old} />
              </span>
              <ArrowRight size={14} className="muted" aria-hidden="true" />
              <span>
                <span className="mono">v{data.new.version}</span> <StatusPill d={data.new} />
              </span>
              <span className="compare-counts">
                <span className="diff-ins">+{formatNumber(data.added)}</span>
                <span className="diff-del-count">−{formatNumber(data.removed)}</span>
                <span className="muted">строк текста</span>
              </span>
            </div>
            {data.meta.length > 0 && (
              <dl className="diff-fields compare-meta">
                {data.meta.map((m) => (
                  <div key={m.title}>
                    <dt>{m.title}</dt>
                    <dd>
                      <Pair before={m.before} after={m.after} />
                    </dd>
                  </div>
                ))}
              </dl>
            )}
          </section>
          <section className="drawer-section">
            <h3>Поля документа · изменилось {formatNumber(data.fields.length)}</h3>
            {data.fields.length === 0 ? (
              <p className="muted">Данные в полях не менялись.</p>
            ) : (
              <div className="table-wrap">
                <table className="table compare-fields">
                  <thead>
                    <tr>
                      <th>Поле</th>
                      <th>Было</th>
                      <th>Стало</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.fields.map((f) => (
                      <tr key={f.key}>
                        <td>
                          <span className="cell-title">{f.title}</span>
                        </td>
                        <td data-label="Было">
                          {f.before ? <span className="diff-del">{f.before}</span> : <span className="muted">—</span>}
                          {f.state_before && f.state_before !== f.state_after && (
                            <div className="cell-sub">
                              <span className={`pill ${STATE_PILL[f.state_before][0]}`}>
                                {STATE_PILL[f.state_before][1]}
                              </span>
                            </div>
                          )}
                        </td>
                        <td data-label="Стало">
                          {f.after ? <span className="diff-ins">{f.after}</span> : <span className="muted">—</span>}
                          {f.state_after && f.state_before !== f.state_after && (
                            <div className="cell-sub">
                              <span className={`pill ${STATE_PILL[f.state_after][0]}`}>
                                {STATE_PILL[f.state_after][1]}
                              </span>
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
          <section className="drawer-section">
            <div className="compare-text-head">
              <h3>Текст документа</h3>
              <label className="check compare-only">
                <input type="checkbox" checked={onlyChanges} onChange={(e) => setOnlyChanges(e.target.checked)} />
                <span>Только изменения</span>
              </label>
            </div>
            {data.text_error && <ErrorAlert message={data.text_error} />}
            {!data.text_error && lines.length === 0 && <p className="muted">Текст не изменился.</p>}
            {lines.map((h, i) => (
              <div key={i} className="text-diff">
                <div className="text-diff-at mono">
                  строка {h.old_start} → {h.new_start}
                </div>
                {h.lines
                  .filter((ln) => !onlyChanges || ln.op !== "same")
                  .map((ln, j) => (
                    <div key={j} className={`text-diff-line ${ln.op}`}>
                      <span className="text-diff-sign" aria-hidden="true">
                        {ln.op === "add" ? "+" : ln.op === "del" ? "−" : " "}
                      </span>
                      <span className="visually-hidden">
                        {ln.op === "add" ? "Добавлено: " : ln.op === "del" ? "Удалено: " : ""}
                      </span>
                      <span>{ln.text}</span>
                    </div>
                  ))}
              </div>
            ))}
            {data.truncated && (
              <p className="muted">Изменений больше — показаны первые. Скачайте обе версии для полного сравнения.</p>
            )}
          </section>
        </>
      )}
    </Drawer>
  );
}
