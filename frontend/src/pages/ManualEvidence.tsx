// Шторка меры: ручные доказательства (файл, интервью, осмотр) и подтверждение статуса.
import {
  BadgeCheck,
  Download,
  FileText,
  MessageSquare,
  Paperclip,
  Plus,
  ScanEye,
  Undo2,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { apiFetch, apiGet, apiSend } from "../lib/api";
import {
  ACCEPT,
  ACCEPT_TEXT,
  CATEGORY_LABELS,
  KIND_LABELS,
  downloadFile,
  formatSize,
  type FileCategory,
  type ManualEvidence,
  type ManualKind,
} from "../lib/evidence";
import { formatDateTime } from "../lib/format";
import {
  STATUS_LABELS,
  STATUS_PILL,
  type ObjectMeasure,
} from "../lib/measures";

function message(e: unknown, fallback: string): string {
  return e instanceof Error ? e.message : fallback;
}

function today(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function formatDay(iso: string | undefined): string {
  if (!iso) return "—";
  const [y, mo, d] = iso.split("-");
  return `${d}.${mo}.${y}`;
}

const KIND_ICON: Record<ManualKind, typeof FileText> = {
  file: Paperclip,
  interview: MessageSquare,
  inspection: ScanEye,
};

// ---------- Ручные доказательства ----------

export function ManualEvidenceSection({
  m,
  canUpload,
  onChanged,
}: {
  m: ObjectMeasure;
  canUpload: boolean;
  onChanged: () => void;
}) {
  const [list, setList] = useState<ManualEvidence[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [withdrawing, setWithdrawing] = useState<ManualEvidence | null>(null);

  const load = useCallback(() => {
    apiGet<ManualEvidence[]>(`/object-measures/${m.id}/evidence`)
      .then((all) => setList(all.filter((e) => e.kind !== "scanner")))
      .catch((e: Error) => setError(e.message));
  }, [m.id]);
  useEffect(load, [load]);

  const active = (list ?? []).filter((e) => !e.withdrawn_at);
  const withdrawn = (list ?? []).filter((e) => e.withdrawn_at);

  return (
    <div className="drawer-section">
      <div className="section-head">
        <h3>Ручные доказательства</h3>
        {canUpload && !adding && (
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => setAdding(true)}
          >
            <Plus size={14} /> Добавить
          </button>
        )}
      </div>
      {error && <ErrorAlert message={error} />}
      {!list && !error && <Loading />}
      {adding && (
        <AddEvidenceForm
          measureId={m.id}
          onCancel={() => setAdding(false)}
          onDone={() => {
            setAdding(false);
            onChanged();
          }}
        />
      )}
      {list && active.length === 0 && !adding && (
        <p className="muted">
          {m.method === "manual"
            ? "Доказательств нет. Организационная мера оценивается по документам, интервью и осмотру."
            : "Доказательств нет. Их прикладывают, когда автоматики «Сканера» недостаточно."}
        </p>
      )}
      {active.length > 0 && (
        <ul className="evidence-cards">
          {active.map((e) => (
            <EvidenceItem
              key={e.id}
              e={e}
              canWithdraw={canUpload}
              onWithdraw={() => setWithdrawing(e)}
            />
          ))}
        </ul>
      )}
      {withdrawn.length > 0 && (
        <details className="evidence-withdrawn">
          <summary>Отозванные ({withdrawn.length})</summary>
          <ul className="evidence-cards">
            {withdrawn.map((e) => (
              <EvidenceItem key={e.id} e={e} canWithdraw={false} />
            ))}
          </ul>
        </details>
      )}
      {withdrawing && (
        <WithdrawDialog
          e={withdrawing}
          onClose={() => setWithdrawing(null)}
          onDone={() => {
            setWithdrawing(null);
            onChanged();
          }}
        />
      )}
    </div>
  );
}

function EvidenceItem({
  e,
  canWithdraw,
  onWithdraw,
}: {
  e: ManualEvidence;
  canWithdraw: boolean;
  onWithdraw?: () => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const Icon = KIND_ICON[e.kind as ManualKind] ?? FileText;
  const d = e.data;

  async function download() {
    if (!e.file) return;
    setBusy(true);
    setError(null);
    try {
      await downloadFile(e.file);
    } catch (err) {
      setError(message(err, "Не удалось скачать файл"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <li className={`evidence-card${e.withdrawn_at ? " is-withdrawn" : ""}`}>
      <div className="evidence-card-head">
        <span className="pill pill-muted">
          <Icon size={12} aria-hidden="true" /> {KIND_LABELS[e.kind]}
          {e.kind === "file" &&
            d.category &&
            ` · ${CATEGORY_LABELS[d.category]}`}
        </span>
        {e.in_confirmation && (
          <span
            className="pill pill-ok"
            title="На него опирается подтверждение меры"
          >
            <BadgeCheck size={12} aria-hidden="true" /> в подтверждении
          </span>
        )}
        {canWithdraw && onWithdraw && (
          <button
            type="button"
            className="link-btn evidence-card-action"
            onClick={onWithdraw}
          >
            <Undo2 size={13} /> Отозвать
          </button>
        )}
      </div>
      <div className="evidence-card-summary">{e.summary}</div>
      {e.file && (
        <div className="evidence-file">
          <span className="mono evidence-file-name" title={e.file.name}>
            {e.file.name}
          </span>
          <span className="muted">{formatSize(e.file.size)}</span>
          <button
            type="button"
            className="btn btn-sm"
            disabled={busy}
            onClick={download}
          >
            <Download size={14} /> Скачать
          </button>
        </div>
      )}
      {(d.held_on || d.participants || d.place) && (
        <dl className="props props-compact">
          {d.held_on && (
            <>
              <dt>Дата</dt>
              <dd>{formatDay(d.held_on)}</dd>
            </>
          )}
          {d.participants && (
            <>
              <dt>{e.kind === "interview" ? "Опрошены" : "Участники"}</dt>
              <dd>{d.participants}</dd>
            </>
          )}
          {d.place && (
            <>
              <dt>Место</dt>
              <dd>{d.place}</dd>
            </>
          )}
        </dl>
      )}
      {d.details && <p className="evidence-details">{d.details}</p>}
      {error && <ErrorAlert message={error} />}
      <div className="cell-sub">
        {e.created_by_name ?? "—"}, {formatDateTime(e.created_at)}
        {e.withdrawn_at && (
          <>
            {" "}
            · отозвал {e.withdrawn_by_name}, {formatDateTime(e.withdrawn_at)}:{" "}
            {e.withdraw_reason}
          </>
        )}
      </div>
    </li>
  );
}

function AddEvidenceForm({
  measureId,
  onCancel,
  onDone,
}: {
  measureId: string;
  onCancel: () => void;
  onDone: () => void;
}) {
  const [kind, setKind] = useState<ManualKind>("file");
  const [summary, setSummary] = useState("");
  const [category, setCategory] = useState<FileCategory>("document");
  const [file, setFile] = useState<File | null>(null);
  const [heldOn, setHeldOn] = useState(today());
  const [participants, setParticipants] = useState("");
  const [place, setPlace] = useState("");
  const [details, setDetails] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const ready =
    summary.trim() !== "" &&
    (kind === "file"
      ? file !== null
      : heldOn !== "" && (kind !== "interview" || participants.trim() !== ""));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const url = `/object-measures/${measureId}/evidence`;
      if (kind === "file" && file) {
        const form = new FormData();
        form.set("kind", "file");
        form.set("summary", summary.trim());
        form.set("category", category);
        if (details.trim()) form.set("details", details.trim());
        form.set("file", file);
        await apiFetch(url, { method: "POST", body: form });
      } else {
        await apiSend("POST", url, {
          kind,
          summary: summary.trim(),
          held_on: heldOn,
          participants: participants.trim() || null,
          place: kind === "inspection" ? place.trim() || null : null,
          details: details.trim() || null,
        });
      }
      onDone();
    } catch (err) {
      setError(message(err, "Не удалось добавить доказательство"));
      setBusy(false);
    }
  }

  return (
    <form className="form-stack drawer-form evidence-form" onSubmit={submit}>
      <div className="seg" role="radiogroup" aria-label="Вид доказательства">
        {(["file", "interview", "inspection"] as ManualKind[]).map((k) => (
          <button
            key={k}
            type="button"
            role="radio"
            aria-checked={kind === k}
            className="seg-btn"
            onClick={() => setKind(k)}
          >
            {KIND_LABELS[k]}
          </button>
        ))}
      </div>
      {error && <ErrorAlert message={error} />}

      {kind === "file" && (
        <>
          <div className="field">
            <span>Файл</span>
            <div className="file-pick">
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => fileRef.current?.click()}
              >
                <Paperclip size={14} /> Выбрать файл
              </button>
              <span className={file ? "mono file-pick-name" : "muted"}>
                {file ? `${file.name} · ${formatSize(file.size)}` : "не выбран"}
              </span>
              <input
                ref={fileRef}
                type="file"
                accept={ACCEPT}
                aria-label="Файл доказательства"
                hidden
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </div>
            <small>
              {ACCEPT_TEXT}, до 50 МБ. Документы с макросами не принимаются.
            </small>
          </div>
          <label className="field">
            <span>Что это</span>
            <select
              className="select"
              value={category}
              onChange={(e) => setCategory(e.target.value as FileCategory)}
            >
              {(Object.keys(CATEGORY_LABELS) as FileCategory[]).map((c) => (
                <option key={c} value={c}>
                  {CATEGORY_LABELS[c]}
                </option>
              ))}
            </select>
          </label>
        </>
      )}

      {kind !== "file" && (
        <div className="form-row">
          <label className="field">
            <span>Дата</span>
            <input
              className="input"
              type="date"
              max={today()}
              value={heldOn}
              onChange={(e) => setHeldOn(e.target.value)}
            />
          </label>
          {kind === "inspection" && (
            <label className="field">
              <span>Место</span>
              <input
                className="input"
                maxLength={300}
                value={place}
                placeholder="Серверная, каб. 105"
                onChange={(e) => setPlace(e.target.value)}
              />
            </label>
          )}
        </div>
      )}
      {kind !== "file" && (
        <label className="field">
          <span>
            {kind === "interview" ? "Кого опрашивали" : "Участники осмотра"}
          </span>
          <input
            className="input"
            maxLength={1000}
            value={participants}
            placeholder="ФИО, должность"
            onChange={(e) => setParticipants(e.target.value)}
          />
        </label>
      )}

      <label className="field">
        <span>Что подтверждает</span>
        <textarea
          className="textarea"
          rows={2}
          maxLength={1000}
          value={summary}
          placeholder={
            kind === "file"
              ? "Например: положение о защите информации, утверждено приказом №12"
              : kind === "interview"
                ? "Вывод по итогам интервью"
                : "Что увидели при осмотре"
          }
          onChange={(e) => setSummary(e.target.value)}
        />
      </label>
      <label className="field">
        <span>
          {kind === "interview"
            ? "Вопросы и ответы"
            : kind === "inspection"
              ? "Протокол осмотра"
              : "Пояснение"}{" "}
          <span className="muted">— необязательно</span>
        </span>
        <textarea
          className="textarea"
          rows={3}
          maxLength={8000}
          value={details}
          onChange={(e) => setDetails(e.target.value)}
        />
      </label>
      <div className="actions">
        <button
          type="submit"
          className="btn btn-primary btn-sm"
          disabled={busy || !ready}
        >
          {busy ? "Сохраняю…" : "Добавить доказательство"}
        </button>
        <button
          type="button"
          className="btn btn-sm"
          disabled={busy}
          onClick={onCancel}
        >
          Отмена
        </button>
      </div>
    </form>
  );
}

function WithdrawDialog({
  e,
  onClose,
  onDone,
}: {
  e: ManualEvidence;
  onClose: () => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(ev: FormEvent) {
    ev.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiSend("POST", `/evidence/${e.id}/withdraw`, {
        reason: reason.trim(),
      });
      onDone();
    } catch (err) {
      setError(message(err, "Не удалось отозвать"));
      setBusy(false);
    }
  }

  return (
    <Modal
      title="Отозвать доказательство"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="submit"
            form="withdraw-form"
            className="btn btn-danger"
            disabled={busy || !reason.trim()}
          >
            Отозвать
          </button>
        </>
      }
    >
      <form id="withdraw-form" className="form-stack" onSubmit={submit}>
        <p>
          «{e.summary}» перестанет считаться доказательством. Запись останется в
          истории меры и в журнале.
          {e.in_confirmation &&
            " На него опирается подтверждение меры — подтверждение будет снято."}
        </p>
        {error && <ErrorAlert message={error} />}
        <label className="field">
          <span>Причина</span>
          <textarea
            className="textarea"
            rows={2}
            maxLength={1000}
            value={reason}
            placeholder="Например: приложена не та редакция документа"
            onChange={(ev) => setReason(ev.target.value)}
          />
        </label>
      </form>
    </Modal>
  );
}

// ---------- Подтверждение ----------

/** Что мешает подтвердить — те же правила, что на сервере (app/domain/confirmation.py). */
export function confirmHint(m: ObjectMeasure): string | null {
  if (m.adaptation === "excluded")
    return "Исключённая при адаптации мера не подтверждается.";
  if (m.status === "unassessed") return "Сначала поставьте статус меры.";
  if (m.status === "implemented" || m.status === "partial") {
    const byScanner = m.auto_status !== null && m.status === m.auto_status;
    if (m.manual_evidence === 0 && !byScanner)
      return m.auto_status === null
        ? "Нужно доказательство: файл, интервью или осмотр."
        : "Статус расходится с «Сканером» — нужно ручное доказательство.";
  }
  return null;
}

export function ConfirmSection({
  m,
  canAssess,
  onChanged,
}: {
  m: ObjectMeasure;
  canAssess: boolean;
  onChanged: () => void;
}) {
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const hint = confirmHint(m);
  const needsComment =
    m.status === "not_applicable" && !m.comment && !comment.trim();

  async function confirm(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiSend("POST", `/object-measures/${m.id}/confirm`, {
        status: m.status,
        comment: comment.trim() || null,
      });
      onChanged();
    } catch (err) {
      setError(message(err, "Не удалось подтвердить"));
      setBusy(false);
    }
  }

  return (
    <div className="drawer-section">
      <h3>Подтверждение</h3>
      {m.confirmed_at && m.confirmed_status ? (
        <div className="confirm-box is-confirmed">
          <BadgeCheck size={18} aria-hidden="true" />
          <div>
            <div>
              Подтверждено:{" "}
              <span className={`pill ${STATUS_PILL[m.confirmed_status]}`}>
                {STATUS_LABELS[m.confirmed_status]}
              </span>
            </div>
            <div className="cell-sub">
              {m.confirmed_by_name}, {formatDateTime(m.confirmed_at)}
            </div>
            {m.confirm_comment && (
              <div className="cell-sub">{m.confirm_comment}</div>
            )}
          </div>
        </div>
      ) : (
        <>
          <p className="muted">
            Статус — предложение. Испытатель подтверждает его, проверив
            доказательства; смена статуса или отзыв доказательства снимает
            подтверждение.
          </p>
          {hint && (
            <div className="alert alert-info">
              <span className="alert-text">{hint}</span>
            </div>
          )}
          {error && <ErrorAlert message={error} />}
          {canAssess && !hint && (
            <form className="form-stack drawer-form" onSubmit={confirm}>
              <label className="field">
                <span>
                  Комментарий{" "}
                  {m.status === "not_applicable" && !m.comment ? (
                    <span className="muted">— почему не применима</span>
                  ) : (
                    <span className="muted">— необязательно</span>
                  )}
                </span>
                <textarea
                  className="textarea"
                  rows={2}
                  maxLength={2000}
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                />
              </label>
              <div className="actions">
                <button
                  type="submit"
                  className="btn btn-primary btn-sm"
                  disabled={busy || needsComment}
                >
                  <BadgeCheck size={14} /> Подтвердить «
                  {STATUS_LABELS[m.status]}»
                </button>
              </div>
            </form>
          )}
        </>
      )}
    </div>
  );
}
