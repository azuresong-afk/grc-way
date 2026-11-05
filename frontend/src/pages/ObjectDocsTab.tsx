import { AlertTriangle, Download, FileText, RefreshCw, Stamp } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Drawer } from "../components/Drawer";
import { EmptyState } from "../components/EmptyState";
import { ErrorAlert, Loading } from "../components/Status";
import { ApiError, apiGet, apiSend } from "../lib/api";
import { formatSize } from "../lib/evidence";
import { formatDateTime, formatNumber } from "../lib/format";
import type { ObjectFull } from "../lib/objects";
import {
  STATE_PILL,
  TAB_TITLES,
  downloadDocument,
  fieldLink,
  isGap,
  type DocBrief,
  type DocField,
  type DocFull,
  type DocTypeDetail,
  type DocumentsList,
  type Unverified,
} from "../lib/objectDocs";

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
        В документе есть записи справочников, не сверенные методистом: {items.map((u) => u.title).join("; ")}.
        Документ получит водяной знак «Проект» и приложение со списком таких записей.
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

function VersionDrawer({ id, obj, onClose }: { id: string; obj: ObjectFull; onClose: () => void }) {
  const [doc, setDoc] = useState<DocFull | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiGet<DocFull>(`/documents/${id}`)
      .then(setDoc)
      .catch((e: Error) => setError(e.message));
  }, [id]);
  return (
    <Drawer
      title={doc ? `${doc.title} · версия ${doc.version}` : "Версия документа"}
      subtitle={doc ? `${formatDateTime(doc.created_at)} · ${doc.created_by_name ?? "—"}` : undefined}
      onClose={onClose}
      footer={doc && <DownloadButtons d={doc} onError={setError} />}
    >
      {error && <ErrorAlert message={error} />}
      {!doc && !error && <Loading />}
      {doc && (
        <>
          <section className="drawer-section">
            <dl className="props">
              <dt>Статус</dt>
              <dd>
                <span className="pill pill-muted">{doc.status_title}</span>
              </dd>
              <dt>Водяной знак</dt>
              <dd>{doc.watermark ? `«Проект»: ${doc.watermark_reasons.join("; ").toLowerCase()}` : "нет"}</dd>
              <dt>Файлы</dt>
              <dd>
                DOCX {formatSize(doc.docx_size)}
                {doc.pdf_size !== null ? ` · PDF ${formatSize(doc.pdf_size)}` : ""}
                {doc.pdf_error && <div className="cell-sub">{doc.pdf_error}</div>}
              </dd>
              <dt>Шаблон</dt>
              <dd className="mono">{doc.template_name}</dd>
            </dl>
            <UnverifiedAlert items={doc.unverified} />
          </section>
          <section className="drawer-section">
            <h3>Из каких данных собрана версия</h3>
            <FieldMap fields={doc.fields} objectId={obj.id} projectId={obj.project_id} links={false} />
          </section>
        </>
      )}
    </Drawer>
  );
}

function TypeCard({
  t,
  obj,
  canEdit,
  pdfAvailable,
  onGenerated,
  onOpen,
}: {
  t: DocTypeDetail;
  obj: ObjectFull;
  canEdit: boolean;
  pdfAvailable: boolean;
  onGenerated: (d: DocFull & { created: boolean }) => void;
  onOpen: (id: string) => void;
}) {
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
      onGenerated(d);
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
            <span className="kpi-label">Водяной знак</span>
            <span className="doc-stat">
              <span className="pill pill-muted">
                <Stamp size={12} /> Проект
              </span>
            </span>
            <span className="cell-sub">{t.watermark_reasons.join("; ")}</span>
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

      <h3 className="doc-section">Версии</h3>
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
                    <span className="pill pill-muted">{v.status_title}</span>
                    {v.watermark && <div className="cell-sub">водяной знак</div>}
                  </td>
                  <td>
                    {v.counts.empty ? (
                      <span className={v.counts.required_empty ? "text-warn" : undefined}>
                        {formatNumber(v.counts.empty)}
                        {v.counts.required_empty > 0 &&
                          ` (обязательных ${formatNumber(v.counts.required_empty)})`}
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
    </section>
  );
}

export function ObjectDocsTab({ obj, editable }: { obj: ObjectFull; editable: boolean }) {
  const [list, setList] = useState<DocumentsList | null>(null);
  const [details, setDetails] = useState<DocTypeDetail[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  const load = useCallback(() => {
    setError(null);
    apiGet<DocumentsList>(`/objects/${obj.id}/documents`)
      .then(async (l) => {
        const d = await Promise.all(
          l.types.map((t) => apiGet<DocTypeDetail>(`/objects/${obj.id}/documents/types/${t.code}`)),
        );
        setList(l);
        setDetails(d);
      })
      .catch((e: Error) => setError(e.message));
  }, [obj.id]);
  useEffect(load, [load]);

  if (error && !list) return <ErrorAlert message={error} onRetry={load} />;
  if (!list || !details) return <Loading />;

  return (
    <>
      {!list.sees_drafts && (
        <div className="alert alert-info">
          <span className="alert-text">
            Здесь появятся утверждённые документы. Проекты документов видят методист, эксперт и утверждающий.
          </span>
        </div>
      )}
      {details.length === 0 ? (
        <EmptyState
          icon={<FileText size={21} />}
          title="Документов для объекта нет"
          text="Каталог документов не содержит документов для нормативного режима этого объекта."
        />
      ) : (
        details.map((t) => (
          <TypeCard
            key={t.code}
            t={t}
            obj={obj}
            canEdit={editable && list.can_edit}
            pdfAvailable={list.pdf_available}
            onGenerated={() => load()}
            onOpen={setOpen}
          />
        ))
      )}
      {open && <VersionDrawer id={open} obj={obj} onClose={() => setOpen(null)} />}
    </>
  );
}
