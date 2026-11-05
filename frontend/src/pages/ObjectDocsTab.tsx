import { AlertTriangle, Download, FileText, GitCompare, RefreshCw, Stamp, Upload } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Drawer } from "../components/Drawer";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { ApiError, apiFetch, apiGet, apiSend } from "../lib/api";
import { formatSize } from "../lib/evidence";
import { formatDateTime, formatNumber } from "../lib/format";
import type { ObjectFull } from "../lib/objects";
import {
  STATE_PILL,
  TAB_TITLES,
  downloadDocument,
  downloadFile,
  fieldLink,
  isGap,
  type DocBrief,
  type DocField,
  type DocFull,
  type DocType,
  type DocTypeDetail,
  type DocumentsList,
  type FontCode,
  type TemplateRow,
  type Unverified,
} from "../lib/objectDocs";
import {
  CompareDrawer,
  ReviewButtons,
  ReviewHistory,
  ReviewModal,
  StatusPill,
  statusNote,
  type ReviewKind,
} from "./DocApproval";

/** Что сравнить: версии документа и пара (было, стало). */
interface CompareTarget {
  versions: DocBrief[];
  pair: [string, string];
}

/** Пара для сравнения по умолчанию: выбранная версия и предыдущая перед ней. */
function defaultPair(versions: DocBrief[], id: string): [string, string] {
  const i = versions.findIndex((v) => v.id === id);
  const prev = versions[i + 1] ?? versions[i - 1];
  return prev ? [prev.id, id] : [id, id];
}

function message(e: unknown, fallback: string): string {
  return e instanceof ApiError || e instanceof Error ? e.message : fallback;
}

function FieldValue({ f }: { f: DocField }) {
  if (f.total !== null) {
    if (f.state === "na") return <span className="muted">список пуст</span>;
    if (!f.missing) return <span>у всех {formatNumber(f.total)}</span>;
    return (
      <>
        <span>
          нет у {formatNumber(f.missing)} из {formatNumber(f.total)}
        </span>
        {f.missing_examples && f.missing_examples.length > 0 && (
          <div className="cell-sub mono">
            {f.missing_examples.join(", ")}
            {f.missing > f.missing_examples.length && " …"}
          </div>
        )}
      </>
    );
  }
  return f.value ? <span className="doc-value">{f.value}</span> : <span className="muted">—</span>;
}

/** Карта «из каких данных собран / какие поля пустые». */
export function FieldMap({
  fields,
  objectId,
  projectId,
  links = true,
}: {
  fields: DocField[];
  objectId: string;
  projectId: string;
  links?: boolean;
}) {
  const gaps = fields.filter(isGap).length;
  const [onlyGaps, setOnlyGaps] = useState(false);
  const shown = onlyGaps ? fields.filter(isGap) : fields;
  return (
    <>
      <div className="chips doc-chips" role="group" aria-label="Поля">
        <button type="button" className="chip" aria-pressed={!onlyGaps} onClick={() => setOnlyGaps(false)}>
          Все поля · {formatNumber(fields.length)}
        </button>
        <button
          type="button"
          className="chip"
          aria-pressed={onlyGaps}
          disabled={gaps === 0}
          onClick={() => setOnlyGaps(true)}
        >
          Нужно заполнить · {formatNumber(gaps)}
        </button>
      </div>
      <div className="table-wrap">
        <table className="table doc-map">
          <thead>
            <tr>
              <th>Поле документа</th>
              <th>Значение</th>
              <th>Откуда берётся</th>
              <th>Состояние</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((f) => {
              const [pill, label] = STATE_PILL[f.state];
              return (
                <tr key={f.key} className={isGap(f) && f.required ? "doc-gap" : undefined}>
                  <td>
                    <span className="cell-title">{f.title}</span>
                    {f.required && <div className="cell-sub">обязательное</div>}
                  </td>
                  <td>
                    <FieldValue f={f} />
                  </td>
                  <td>
                    <span className="doc-source">{f.source}</span>
                    {links && isGap(f) && (
                      <div className="cell-sub">
                        <Link to={fieldLink(f, objectId, projectId)}>Заполнить: {TAB_TITLES[f.tab]}</Link>
                      </div>
                    )}
                  </td>
                  <td>
                    <span className={`pill ${pill}`}>{label}</span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

function UnverifiedAlert({ items }: { items: Unverified[] }) {
  if (items.length === 0) return null;
  return (
    <div className="alert alert-warn" role="status">
      <AlertTriangle size={15} />
      <span className="alert-text">
        В документе есть записи справочников, не сверенные методистом: {items.map((u) => u.title).join("; ")}. Такой
        документ выходит с водяным знаком «Проект» и приложением со списком этих записей.
      </span>
    </div>
  );
}

function DownloadButtons({ d, onError }: { d: DocBrief; onError: (m: string) => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  async function get(format: "docx" | "pdf") {
    setBusy(format);
    try {
      await downloadDocument(d, format);
    } catch (e) {
      onError(message(e, "Не удалось скачать документ"));
    } finally {
      setBusy(null);
    }
  }
  return (
    <div className="btn-row">
      <button type="button" className="btn btn-sm" disabled={busy !== null} onClick={() => void get("docx")}>
        <Download size={14} /> DOCX
      </button>
      <button
        type="button"
        className="btn btn-sm"
        disabled={busy !== null || d.pdf_size === null}
        title={d.pdf_error ?? undefined}
        onClick={() => void get("pdf")}
      >
        <Download size={14} /> PDF
      </button>
    </div>
  );
}

function VersionDrawer({
  id,
  obj,
  onClose,
  onChanged,
  onCompare,
}: {
  id: string;
  obj: ObjectFull;
  onClose: () => void;
  onChanged: () => void;
  onCompare: (c: CompareTarget) => void;
}) {
  const [doc, setDoc] = useState<DocFull | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [step, setStep] = useState<ReviewKind | null>(null);
  useEffect(() => {
    setDoc(null);
    apiGet<DocFull>(`/documents/${id}`)
      .then(setDoc)
      .catch((e: Error) => setError(e.message));
  }, [id]);
  return (
    <Drawer
      title={doc ? `${doc.title} · версия ${doc.version}` : "Версия документа"}
      subtitle={doc ? `${formatDateTime(doc.created_at)} · ${doc.created_by_name ?? "—"}` : undefined}
      onClose={onClose}
      footer={
        doc && (
          <div className="doc-drawer-foot">
            <div className="btn-row">
              {doc.siblings.length > 1 && (
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() =>
                    onCompare({
                      versions: doc.siblings,
                      pair: defaultPair(doc.siblings, doc.id),
                    })
                  }
                >
                  <GitCompare size={14} /> Сравнить
                </button>
              )}
              <DownloadButtons d={doc} onError={setError} />
            </div>
            <div className="btn-row">
              <ReviewButtons doc={doc} onPick={setStep} />
            </div>
          </div>
        )
      }
    >
      {error && <ErrorAlert message={error} />}
      {!doc && !error && <Loading />}
      {doc && (
        <>
          <section className="drawer-section">
            <dl className="props">
              <dt>Статус</dt>
              <dd>
                <StatusPill d={doc} />
                {statusNote(doc) && <div className="cell-sub">{statusNote(doc)}</div>}
                {doc.approval_comment && <div className="cell-sub">«{doc.approval_comment}»</div>}
                {doc.unverified_acknowledged && (
                  <div className="cell-sub text-warn">утверждён с несверенными записями справочников</div>
                )}
              </dd>
              {doc.actions.approve_blocker && (
                <>
                  <dt>Утверждение</dt>
                  <dd className="text-warn">{doc.actions.approve_blocker}</dd>
                </>
              )}
              <dt>Водяной знак</dt>
              <dd>{doc.watermark ? `«Проект»: ${doc.watermark_reasons.join("; ").toLowerCase()}` : "нет"}</dd>
              <dt>Файлы</dt>
              <dd>
                DOCX {formatSize(doc.docx_size)}
                {doc.pdf_size !== null ? ` · PDF ${formatSize(doc.pdf_size)}` : ""}
                {doc.pdf_error && <div className="cell-sub">{doc.pdf_error}</div>}
              </dd>
              <dt>Шаблон</dt>
              <dd>
                {doc.template_custom ? "Свой: " : "Встроенный: "}
                <span className="mono">{doc.template_name}</span>
              </dd>
              <dt>Шрифт</dt>
              <dd>{doc.font_title ?? "из своего шаблона"}</dd>
            </dl>
            <UnverifiedAlert items={doc.unverified} />
          </section>
          <section className="drawer-section">
            <h3>История согласования</h3>
            <ReviewHistory items={doc.reviews} />
          </section>
          <section className="drawer-section">
            <h3>Из каких данных собрана версия</h3>
            <FieldMap fields={doc.fields} objectId={obj.id} projectId={obj.project_id} links={false} />
          </section>
        </>
      )}
      {doc && step && (
        <ReviewModal
          doc={doc}
          kind={step}
          onClose={() => setStep(null)}
          onDone={(d) => {
            setStep(null);
            setDoc(d);
            onChanged();
          }}
        />
      )}
    </Drawer>
  );
}

function TemplateModal({ t, onClose, onChanged }: { t: DocTypeDetail; onClose: () => void; onChanged: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ref = t.template_ref;

  async function run(action: () => Promise<unknown>, fallback: string) {
    setBusy(true);
    setError(null);
    try {
      await action();
      onChanged();
      onClose();
    } catch (e) {
      setError(message(e, fallback));
      setBusy(false);
    }
  }

  const upload = () =>
    run(async () => {
      if (!file) return;
      const form = new FormData();
      form.set("file", file);
      if (comment.trim()) form.set("comment", comment.trim());
      const res = await apiFetch(`/document-templates/${t.code}`, {
        method: "POST",
        body: form,
      });
      return (await res.json()) as TemplateRow;
    }, "Не удалось загрузить шаблон");

  return (
    <Modal
      title={`Шаблон: ${t.title}`}
      onClose={onClose}
      footer={
        <>
          {ref.custom && (
            <button
              type="button"
              className="btn btn-ghost"
              disabled={busy}
              onClick={() =>
                void run(() => apiSend("POST", `/document-templates/${t.code}/reset`), "Не удалось вернуть шаблон")
              }
            >
              Вернуть встроенный
            </button>
          )}
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" disabled={!file || busy} onClick={() => void upload()}>
            <Upload size={14} /> {busy ? "Проверяем…" : "Загрузить"}
          </button>
        </>
      }
    >
      <p className="muted">
        Свой (фирменный) шаблон — DOCX с полями вида <span className="mono">{"{{ object.name }}"}</span>. Он действует
        для этого документа во всех проектах; шрифты и оформление берутся из шаблона. Возьмите за основу встроенный
        шаблон — в нём поля уже расставлены.
      </p>
      <div className="btn-row">
        <button
          type="button"
          className="btn btn-sm"
          onClick={() =>
            void downloadFile(`/document-templates/${t.code}/builtin`, `Шаблон — ${t.title}.docx`).catch((e) =>
              setError(message(e, "Не удалось скачать шаблон")),
            )
          }
        >
          <Download size={14} /> Встроенный шаблон
        </button>
        {ref.custom && ref.id && (
          <button
            type="button"
            className="btn btn-sm"
            onClick={() =>
              void downloadFile(`/document-templates/files/${ref.id}`, ref.name).catch((e) =>
                setError(message(e, "Не удалось скачать шаблон")),
              )
            }
          >
            <Download size={14} /> Текущий свой
          </button>
        )}
      </div>
      <dl className="props">
        <dt>Сейчас действует</dt>
        <dd>
          {ref.custom ? (
            <>
              свой: <span className="mono">{ref.name}</span>
              <div className="cell-sub">
                {ref.uploaded_at ? formatDateTime(ref.uploaded_at) : ""} · {ref.uploaded_by_name ?? "—"}
                {ref.comment ? ` · ${ref.comment}` : ""}
              </div>
            </>
          ) : (
            <>
              встроенный: <span className="mono">{ref.name}</span>
            </>
          )}
        </dd>
      </dl>
      <label className="field">
        <span>Файл DOCX</span>
        <input
          className="input"
          type="file"
          accept=".docx,application/vnd.openxmlformats-officedocument.wordprocessingml.document"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
        <small>До 10 МБ, без макросов. Неизвестные поля и ошибки в полях покажем сразу.</small>
      </label>
      <label className="field">
        <span>Комментарий</span>
        <input className="input" value={comment} maxLength={1000} onChange={(e) => setComment(e.target.value)} />
      </label>
      {error && <ErrorAlert message={error} />}
    </Modal>
  );
}

function TypeCard({
  t,
  obj,
  canEdit,
  pdfAvailable,
  fontTitle,
  onGenerated,
  onOpen,
  onCompare,
}: {
  t: DocTypeDetail;
  obj: ObjectFull;
  canEdit: boolean;
  pdfAvailable: boolean;
  fontTitle: string | null;
  onGenerated: () => void;
  onOpen: (id: string) => void;
  onCompare: (c: CompareTarget) => void;
}) {
  const [templateOpen, setTemplateOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const filled = t.counts.total - t.counts.empty;

  async function generate() {
    setBusy(true);
    setError(null);
    setNote(null);
    try {
      const d = await apiSend<DocFull & { created: boolean }>("POST", `/objects/${obj.id}/documents`, {
        type: t.code,
      });
      setNote(
        d.created
          ? `Сформирована версия ${d.version}${d.pdf_size === null ? " (только DOCX)" : ""}`
          : `Данные не менялись — актуальна версия ${d.version}`,
      );
      onGenerated();
    } catch (e) {
      setError(message(e, "Не удалось сформировать документ"));
    } finally {
      setBusy(false);
    }
  }

  const nextVersion = (t.latest?.version ?? 0) + 1;
  return (
    <section className="card doc-card">
      <div className="card-head">
        <div>
          <h2>
            <FileText size={16} className="doc-icon" /> {t.title}
          </h2>
          <div className="cell-sub">{t.description}</div>
        </div>
        {canEdit && (
          <button
            type="button"
            className="btn btn-primary btn-sm"
            disabled={busy || !t.template_found || (!t.changed && t.latest !== null)}
            title={!t.changed && t.latest ? "Данные не менялись после последней версии" : undefined}
            onClick={() => void generate()}
          >
            <RefreshCw size={14} className={busy ? "spin" : undefined} />
            {busy ? "Формируется…" : `Сформировать версию ${nextVersion}`}
          </button>
        )}
      </div>
      <div className="card-pad doc-body">
        {error && <ErrorAlert message={error} />}
        {note && (
          <div className="alert alert-ok" role="status">
            <span className="alert-text">{note}</span>
          </div>
        )}
        {!t.template_found && (
          <div className="alert alert-danger">
            <span className="alert-text">Шаблон {t.template} не найден на сервере.</span>
          </div>
        )}
        <div className="doc-stats">
          <div>
            <span className="kpi-label">Заполнено полей</span>
            <span className="doc-stat">
              {formatNumber(filled)} <span className="muted">из {formatNumber(t.counts.total)}</span>
            </span>
          </div>
          <div>
            <span className="kpi-label">Обязательных пустых</span>
            <span className={`doc-stat${t.counts.required_empty ? " warn" : ""}`}>
              {formatNumber(t.counts.required_empty)}
            </span>
          </div>
          <div>
            <span className="kpi-label">Последняя версия</span>
            <span className="doc-stat">
              {t.latest ? (
                <>
                  {t.latest.version}{" "}
                  {t.changed ? (
                    <span className="pill pill-warn">Данные изменились</span>
                  ) : (
                    <span className="pill pill-ok">Актуальна</span>
                  )}
                </>
              ) : (
                <span className="muted">нет</span>
              )}
            </span>
          </div>
          <div>
            <span className="kpi-label">Шаблон</span>
            <span className="doc-stat">
              <span className={`pill ${t.template_ref.custom ? "pill-info" : "pill-muted"}`}>
                {t.template_ref.custom ? "Свой" : "Встроенный"}
              </span>
            </span>
            <span className="cell-sub">
              {t.template_ref.custom ? t.template_ref.name : `шрифт ${fontTitle ?? "—"}`}
              {canEdit && (
                <>
                  {" · "}
                  <button type="button" className="link-btn" onClick={() => setTemplateOpen(true)}>
                    {t.template_ref.custom ? "заменить" : "загрузить свой"}
                  </button>
                </>
              )}
            </span>
          </div>
          <div>
            <span className="kpi-label">Согласование</span>
            <span className="doc-stat">
              {t.latest ? <StatusPill d={t.latest} /> : <span className="muted">нет версий</span>}
            </span>
            <span className="cell-sub">
              {t.approved
                ? `действует v${t.approved.version}${t.approved.approved_at ? ` от ${formatDateTime(t.approved.approved_at)}` : ""}`
                : "утверждённой версии нет"}
            </span>
          </div>
          <div>
            <span className="kpi-label">Водяной знак</span>
            <span className="doc-stat">
              <span className="pill pill-muted">
                <Stamp size={12} /> Проект
              </span>
            </span>
            <span className="cell-sub">{t.watermark_reasons.map((r, i) => (i ? r.toLowerCase() : r)).join("; ")}</span>
          </div>
        </div>
        {!pdfAvailable && (
          <div className="alert alert-info">
            <span className="alert-text">
              PDF не формируется: на сервере нет LibreOffice. Документ доступен в DOCX.
            </span>
          </div>
        )}
        <UnverifiedAlert items={t.unverified} />
      </div>

      <h3 className="doc-section">Из каких данных собирается</h3>
      <div className="doc-map-wrap">
        <FieldMap fields={t.fields} objectId={obj.id} projectId={obj.project_id} />
      </div>

      <div className="doc-section doc-section-row">
        <h3>Версии</h3>
        {t.versions.length > 1 && (
          <button
            type="button"
            className="btn btn-sm"
            onClick={() =>
              onCompare({
                versions: t.versions,
                pair: [t.versions[1]!.id, t.versions[0]!.id],
              })
            }
          >
            <GitCompare size={14} /> Сравнить версии
          </button>
        )}
      </div>
      {t.versions.length === 0 ? (
        <div className="card-pad muted">Документ ещё не формировался.</div>
      ) : (
        <div className="table-wrap">
          <table className="table doc-versions">
            <thead>
              <tr>
                <th>Версия</th>
                <th>Сформирована</th>
                <th>Статус</th>
                <th>Пустых полей</th>
                <th className="cell-actions">Файлы</th>
              </tr>
            </thead>
            <tbody>
              {t.versions.map((v) => (
                <tr key={v.id} className="clickable" onClick={() => onOpen(v.id)}>
                  <td className="mono">v{v.version}</td>
                  <td>
                    {formatDateTime(v.created_at)}
                    <div className="cell-sub">{v.created_by_name ?? "—"}</div>
                  </td>
                  <td>
                    <StatusPill d={v} />
                    {statusNote(v) && <div className="cell-sub">{statusNote(v)}</div>}
                    {v.watermark && <div className="cell-sub">водяной знак «Проект»</div>}
                  </td>
                  <td>
                    {v.counts.empty ? (
                      <span className={v.counts.required_empty ? "text-warn" : undefined}>
                        {formatNumber(v.counts.empty)}
                        {v.counts.required_empty > 0 && ` (обязательных ${formatNumber(v.counts.required_empty)})`}
                      </span>
                    ) : (
                      <span className="muted">нет</span>
                    )}
                  </td>
                  <td className="cell-actions" onClick={(e) => e.stopPropagation()}>
                    <DownloadButtons d={v} onError={setError} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {templateOpen && <TemplateModal t={t} onClose={() => setTemplateOpen(false)} onChanged={onGenerated} />}
    </section>
  );
}

function versionPill(t: DocType) {
  if (!t.latest) return <span className="muted">нет</span>;
  return (
    <>
      <span className="mono">v{t.latest.version}</span> <StatusPill d={t.latest} />
      {t.changed && <div className="cell-sub text-warn">данные изменились</div>}
    </>
  );
}

/** Комплект: девять документов с готовностью, версией и шаблоном. */
function KitTable({
  types,
  selected,
  onSelect,
}: {
  types: DocType[];
  selected: string;
  onSelect: (c: string) => void;
}) {
  return (
    <div className="table-wrap">
      <table className="table doc-kit">
        <thead>
          <tr>
            <th>Документ</th>
            <th>Заполнено полей</th>
            <th>Последняя версия</th>
            <th>Утверждена</th>
            <th>Шаблон</th>
          </tr>
        </thead>
        <tbody>
          {types.map((t, i) => {
            const filled = t.counts.total - t.counts.empty;
            return (
              <tr
                key={t.code}
                className={`clickable${t.code === selected ? " selected" : ""}`}
                aria-selected={t.code === selected}
                onClick={() => onSelect(t.code)}
              >
                <td>
                  <span className="doc-kit-doc">
                    <span className="doc-kit-num">{i + 1}</span>
                    <button type="button" className="link-btn cell-title" onClick={() => onSelect(t.code)}>
                      {t.title}
                    </button>
                  </span>
                </td>
                <td>
                  {formatNumber(filled)} <span className="muted">из {formatNumber(t.counts.total)}</span>
                  {t.counts.required_empty > 0 && (
                    <div className="cell-sub text-warn">
                      обязательных пустых: {formatNumber(t.counts.required_empty)}
                    </div>
                  )}
                </td>
                <td>{versionPill(t)}</td>
                <td>
                  {t.approved ? (
                    <>
                      <span className="mono">v{t.approved.version}</span>
                      {t.approved.approved_at && (
                        <div className="cell-sub">{formatDateTime(t.approved.approved_at)}</div>
                      )}
                    </>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
                <td>
                  <span className={`pill ${t.template_ref.custom ? "pill-info" : "pill-muted"}`}>
                    {t.template_ref.custom ? "Свой" : "Встроенный"}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function ObjectDocsTab({ obj, editable }: { obj: ObjectFull; editable: boolean }) {
  const [params, setParams] = useSearchParams();
  const [list, setList] = useState<DocumentsList | null>(null);
  const [detail, setDetail] = useState<DocTypeDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [compare, setCompare] = useState<CompareTarget | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const selected = list?.types.find((t) => t.code === params.get("doc"))?.code ?? list?.types[0]?.code ?? null;

  const load = useCallback(() => {
    setError(null);
    apiGet<DocumentsList>(`/objects/${obj.id}/documents`)
      .then(setList)
      .catch((e: Error) => setError(e.message));
  }, [obj.id]);
  useEffect(load, [load]);

  useEffect(() => {
    if (!selected || !list) return;
    let alive = true;
    apiGet<DocTypeDetail>(`/objects/${obj.id}/documents/types/${selected}`)
      .then((d) => alive && setDetail(d))
      .catch((e: Error) => alive && setError(e.message));
    return () => {
      alive = false;
    };
  }, [obj.id, selected, list]);

  function select(code: string) {
    const next = new URLSearchParams(params);
    next.set("doc", code);
    setParams(next, { replace: true });
  }

  async function setFont(font: FontCode) {
    if (!list || font === list.font) return;
    setBusy("font");
    setNote(null);
    try {
      await apiSend("PUT", `/objects/${obj.id}/documents/settings`, { font });
      load();
    } catch (e) {
      setError(message(e, "Не удалось сменить шрифт"));
    } finally {
      setBusy(null);
    }
  }

  async function generateChanged() {
    if (!list) return;
    const todo = list.types.filter((t) => t.changed && t.template_found);
    setBusy("all");
    setNote(null);
    setError(null);
    let made = 0;
    try {
      for (const t of todo) {
        const d = await apiSend<DocFull & { created: boolean }>("POST", `/objects/${obj.id}/documents`, {
          type: t.code,
        });
        if (d.created) made += 1;
      }
      setNote(`Сформировано новых версий: ${formatNumber(made)}`);
    } catch (e) {
      setError(message(e, "Не удалось сформировать документы"));
    } finally {
      setBusy(null);
      load();
    }
  }

  if (error && !list) return <ErrorAlert message={error} onRetry={load} />;
  if (!list) return <Loading />;

  const canEdit = editable && list.can_edit;
  const changed = list.types.filter((t) => t.changed && t.template_found).length;
  const fontTitle = list.fonts.find((f) => f.code === list.font)?.title ?? null;

  return (
    <>
      {!list.sees_drafts && (
        <div className="alert alert-info">
          <span className="alert-text">
            Здесь — утверждённые документы и их прежние версии. Проекты и документы на согласовании видят методист,
            эксперт и утверждающий.
          </span>
        </div>
      )}
      {list.types.length === 0 ? (
        <EmptyState
          icon={<FileText size={21} />}
          title="Документов для объекта нет"
          text="Каталог документов не содержит документов для нормативного режима этого объекта."
        />
      ) : (
        <>
          <section className="card doc-kit-card">
            <div className="card-head">
              <div>
                <h2>Комплект документов</h2>
                <div className="cell-sub">
                  {formatNumber(list.types.length)} документов · утверждено{" "}
                  {formatNumber(list.types.filter((t) => t.approved).length)}
                  {list.sees_drafts && (
                    <>
                      {" "}
                      · сформировано {formatNumber(list.types.filter((t) => t.latest).length)} · на согласовании{" "}
                      {formatNumber(list.types.filter((t) => t.latest?.status === "review").length)} · требуют новой
                      версии {formatNumber(changed)}
                    </>
                  )}
                </div>
              </div>
              <div className="doc-kit-tools">
                <div className="doc-font">
                  <span className="kpi-label" id="doc-font-label">
                    Шрифт
                  </span>
                  <div className="seg" role="radiogroup" aria-labelledby="doc-font-label">
                    {list.fonts.map((f) => (
                      <button
                        key={f.code}
                        type="button"
                        role="radio"
                        className="seg-btn"
                        aria-checked={f.code === list.font}
                        disabled={!canEdit || busy !== null}
                        onClick={() => void setFont(f.code)}
                      >
                        {f.title}
                      </button>
                    ))}
                  </div>
                </div>
                {canEdit && (
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    disabled={busy !== null || changed === 0}
                    onClick={() => void generateChanged()}
                  >
                    <RefreshCw size={14} className={busy === "all" ? "spin" : undefined} />
                    {busy === "all" ? "Формируются…" : `Сформировать изменившиеся · ${formatNumber(changed)}`}
                  </button>
                )}
              </div>
            </div>
            {(error || note) && (
              <div className="card-pad">
                {error && <ErrorAlert message={error} />}
                {note && (
                  <div className="alert alert-ok" role="status">
                    <span className="alert-text">{note}</span>
                  </div>
                )}
              </div>
            )}
            <KitTable types={list.types} selected={selected ?? ""} onSelect={select} />
            <div className="card-pad cell-sub">
              Шрифт применяется к встроенным шаблонам; свой шаблон оформляется своими шрифтами. После смены шрифта
              документы нужно сформировать заново.
            </div>
          </section>
          {detail && detail.code === selected ? (
            <TypeCard
              key={detail.code}
              t={detail}
              obj={obj}
              canEdit={canEdit}
              pdfAvailable={list.pdf_available}
              fontTitle={fontTitle}
              onGenerated={load}
              onOpen={setOpen}
              onCompare={setCompare}
            />
          ) : (
            <Loading />
          )}
        </>
      )}
      {open && !compare && (
        <VersionDrawer id={open} obj={obj} onClose={() => setOpen(null)} onChanged={load} onCompare={setCompare} />
      )}
      {compare && <CompareDrawer versions={compare.versions} initial={compare.pair} onClose={() => setCompare(null)} />}
    </>
  );
}
