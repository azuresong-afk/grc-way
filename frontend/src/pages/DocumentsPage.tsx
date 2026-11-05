import { CheckCheck, ExternalLink, FileText, Pencil } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Drawer } from "../components/Drawer";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { VerifyBadge } from "../components/VerifyBadge";
import { apiGet, apiSend } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ORIGIN_LABELS } from "../lib/classification";
import { formatDateTime } from "../lib/format";
import { DOC_STATUS, type RefDocument, type Source } from "../lib/vulnCriticality";

interface Detail extends RefDocument {
  revisions: { revision: number; changed_by_name: string | null; changed_at: string; comment: string | null }[];
}

function issuedText(d: RefDocument): string {
  const parts: string[] = [];
  if (d.issuer) parts.push(d.issuer);
  if (d.issued) parts.push(`от ${d.issued.split("-").reverse().join(".")}`);
  if (d.number) parts.push(`№ ${d.number}`);
  return parts.join(" ");
}

function basisText(s: Source): string {
  return [s.document, s.clause && `п. ${s.clause}`].filter(Boolean).join(", ");
}

export function DocumentsPage() {
  const [docs, setDocs] = useState<RefDocument[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [opened, setOpened] = useState<string | null>(null);

  const load = useCallback(() => {
    setError(null);
    apiGet<RefDocument[]>("/refs/documents")
      .then(setDocs)
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  const byCode = new Map((docs ?? []).map((d) => [d.code, d]));
  const unverified = docs?.filter((d) => !d.verified).length ?? 0;

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            <Link to="/refs">Справочники</Link> / Нормативные документы
          </div>
          <h1>Нормативные документы</h1>
        </div>
      </div>

      {error && <ErrorAlert message={error} onRetry={load} />}
      {docs === null && !error && <Loading />}
      {docs?.length === 0 && (
        <section className="card">
          <EmptyState
            icon={<FileText size={21} />}
            title="Документы не загружены"
            text="Список загружается из reference/normative при старте сервиса."
          />
        </section>
      )}

      {docs && docs.length > 0 && (
        <>
          {unverified > 0 && (
            <div className="alert alert-warn">
              <span className="alert-text">
                Не сверено методистом: {unverified} из {docs.length}. Документ, который не применяется, остаётся в
                списке со ссылкой на заменивший его и основанием.
              </span>
            </div>
          )}
          <section className="card">
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Документ</th>
                    <th>Статус</th>
                    <th>Основание</th>
                    <th>Сверка</th>
                  </tr>
                </thead>
                <tbody>
                  {docs.map((d) => (
                    <tr
                      key={d.code}
                      className={`clickable${opened === d.code ? " selected" : ""}${d.status === "not_applicable" ? " row-muted" : ""}`}
                      onClick={() => setOpened(d.code)}
                    >
                      <td>
                        <button type="button" className="link-btn cell-title" onClick={() => setOpened(d.code)}>
                          {d.short}
                        </button>
                        <div className="cell-sub">
                          {d.title}
                          {issuedText(d) && ` · ${issuedText(d)}`}
                        </div>
                      </td>
                      <td className="nowrap">
                        <span className={d.status === "active" ? "pill pill-ok" : "pill pill-muted"}>
                          {DOC_STATUS[d.status]}
                        </span>
                        {d.replaced_by && (
                          <div className="cell-sub">заменён: {byCode.get(d.replaced_by)?.short ?? d.replaced_by}</div>
                        )}
                        {d.replaces.length > 0 && (
                          <div className="cell-sub">
                            заменяет: {d.replaces.map((c) => byCode.get(c)?.short ?? c).join(", ")}
                          </div>
                        )}
                      </td>
                      <td className="cell-sub">
                        {d.status === "not_applicable" ? basisText(d.source) : d.source.note}
                      </td>
                      <td>
                        <VerifyBadge verified={d.verified} by={d.verified_by_name} at={d.verified_at} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      {opened && docs && (
        <DocumentDrawer
          code={opened}
          docs={docs}
          onClose={() => setOpened(null)}
          onChanged={(d) => setDocs((list) => list?.map((x) => (x.code === d.code ? { ...x, ...d } : x)) ?? null)}
        />
      )}
    </>
  );
}

function DocumentDrawer({
  code,
  docs,
  onClose,
  onChanged,
}: {
  code: string;
  docs: RefDocument[];
  onClose: () => void;
  onChanged: (d: Detail) => void;
}) {
  const { can } = useAuth();
  const [d, setD] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);

  useEffect(() => {
    setD(null);
    apiGet<Detail>(`/refs/documents/${encodeURIComponent(code)}`)
      .then(setD)
      .catch((e: Error) => setError(e.message));
  }, [code]);

  const changed = (x: Detail) => {
    setD(x);
    onChanged(x);
  };

  async function verify() {
    if (!d) return;
    try {
      changed(await apiSend<Detail>("POST", `/refs/documents/${encodeURIComponent(code)}/verify`, { revision: d.revision }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось отметить сверку");
    }
  }

  const short = (c: string) => docs.find((x) => x.code === c)?.short ?? c;
  return (
    <Drawer
      title={d?.short ?? code}
      subtitle={d ? `${DOC_STATUS[d.status]} · ревизия ${d.revision}` : undefined}
      onClose={onClose}
      footer={
        d && (
          <>
            {can("refs.manage") && (
              <button type="button" className="btn" onClick={() => setEditing(true)}>
                <Pencil size={15} /> Изменить
              </button>
            )}
            {can("refs.verify") && !d.verified && (
              <button type="button" className="btn btn-primary" onClick={verify}>
                <CheckCheck size={15} /> Сверено
              </button>
            )}
          </>
        )
      }
    >
      {error && <ErrorAlert message={error} />}
      {!d && !error && <Loading />}
      {d && (
        <>
          <div className="drawer-section">
            <VerifyBadge verified={d.verified} />
            {d.verified && (
              <p className="muted">
                Сверил(а) {d.verified_by_name}, {formatDateTime(d.verified_at)}
              </p>
            )}
          </div>
          <div className="drawer-section">
            <dl className="props">
              <dt>Наименование</dt>
              <dd>{d.title}</dd>
              <dt>Реквизиты</dt>
              <dd>{issuedText(d) || "—"}</dd>
              <dt>Статус</dt>
              <dd>
                {DOC_STATUS[d.status]}
                {d.replaced_by && ` — заменён документом «${short(d.replaced_by)}»`}
                {d.replaces.length > 0 && <div className="cell-sub">Заменяет: {d.replaces.map(short).join(", ")}</div>}
              </dd>
              <dt>Основание</dt>
              <dd>
                {basisText(d.source) || "—"}
                {d.source.note && <div className="cell-sub">{d.source.note}</div>}
              </dd>
              {d.url && (
                <>
                  <dt>Текст</dt>
                  <dd>
                    <a href={d.url} target="_blank" rel="noreferrer noopener">
                      Открыть <ExternalLink size={12} />
                    </a>
                  </dd>
                </>
              )}
              <dt>Происхождение</dt>
              <dd>{ORIGIN_LABELS[d.origin] ?? d.origin}</dd>
            </dl>
          </div>
          {d.revisions.length > 0 && (
            <div className="drawer-section">
              <h3>История правок</h3>
              <ul className="history">
                {d.revisions.map((r) => (
                  <li key={r.revision}>
                    <span>
                      Ревизия {r.revision} → {r.revision + 1}: {r.changed_by_name ?? "—"}, {formatDateTime(r.changed_at)}
                    </span>
                    {r.comment && <span className="cell-sub">{r.comment}</span>}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
      {editing && d && (
        <DocumentDialog
          doc={d}
          docs={docs}
          onClose={() => setEditing(false)}
          onSaved={(x) => {
            setEditing(false);
            changed(x);
          }}
        />
      )}
    </Drawer>
  );
}

function DocumentDialog({
  doc,
  docs,
  onClose,
  onSaved,
}: {
  doc: Detail;
  docs: RefDocument[];
  onClose: () => void;
  onSaved: (d: Detail) => void;
}) {
  const [f, setF] = useState({
    short: doc.short,
    title: doc.title,
    issued: doc.issued ?? "",
    number: doc.number ?? "",
    url: doc.url ?? "",
    status: doc.status,
    replaced_by: doc.replaced_by ?? "",
    document: doc.source.document ?? "",
    clause: doc.source.clause ?? "",
    note: doc.source.note ?? "",
  });
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);
  const set = (k: keyof typeof f, v: string) => setF((p) => ({ ...p, [k]: v }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      onSaved(
        await apiSend<Detail>("PATCH", `/refs/documents/${encodeURIComponent(doc.code)}`, {
          short: f.short.trim(),
          title: f.title.trim(),
          issued: f.issued || null,
          number: f.number.trim(),
          url: f.url.trim(),
          status: f.status,
          replaced_by: f.status === "not_applicable" ? f.replaced_by : "",
          source: f.document.trim()
            ? { ...doc.source, document: f.document.trim(), clause: f.clause.trim() || null, note: f.note.trim() || null }
            : undefined,
          comment: comment.trim(),
        }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось сохранить");
    }
  }

  return (
    <Modal
      title={`Документ «${doc.short}»`}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" form="doc-edit" className="btn btn-primary" disabled={!comment.trim()}>
            Сохранить
          </button>
        </>
      }
    >
      <form id="doc-edit" className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <label className="field">
          <span>Краткое наименование</span>
          <input className="input" value={f.short} required onChange={(e) => set("short", e.target.value)} />
        </label>
        <label className="field">
          <span>Полное наименование</span>
          <textarea className="textarea" rows={2} value={f.title} required onChange={(e) => set("title", e.target.value)} />
        </label>
        <div className="form-row">
          <label className="field">
            <span>Дата утверждения</span>
            <input className="input" type="date" value={f.issued} onChange={(e) => set("issued", e.target.value)} />
          </label>
          <label className="field">
            <span>Номер</span>
            <input className="input" value={f.number} onChange={(e) => set("number", e.target.value)} />
          </label>
        </div>
        <label className="field">
          <span>Ссылка на текст</span>
          <input className="input" value={f.url} onChange={(e) => set("url", e.target.value)} />
        </label>
        <div className="form-row">
          <label className="field">
            <span>Статус</span>
            <select className="select" value={f.status} onChange={(e) => set("status", e.target.value)}>
              <option value="active">Применяется</option>
              <option value="not_applicable">Не применяется</option>
            </select>
          </label>
          {f.status === "not_applicable" && (
            <label className="field">
              <span>Заменён документом</span>
              <select className="select" value={f.replaced_by} onChange={(e) => set("replaced_by", e.target.value)}>
                <option value="">—</option>
                {docs
                  .filter((x) => x.code !== doc.code)
                  .map((x) => (
                    <option key={x.code} value={x.code}>
                      {x.short}
                    </option>
                  ))}
              </select>
            </label>
          )}
        </div>
        <label className="field">
          <span>Основание: документ</span>
          <input className="input" value={f.document} onChange={(e) => set("document", e.target.value)} />
        </label>
        <div className="form-row">
          <label className="field">
            <span>Пункт</span>
            <input className="input" value={f.clause} onChange={(e) => set("clause", e.target.value)} />
          </label>
          <label className="field">
            <span>Примечание</span>
            <input className="input" value={f.note} onChange={(e) => set("note", e.target.value)} />
          </label>
        </div>
        <label className="field">
          <span>Основание правки</span>
          <input className="input" value={comment} maxLength={1000} required onChange={(e) => setComment(e.target.value)} />
          <small>Правка создаёт новую ревизию и снимает отметку о сверке.</small>
        </label>
      </form>
    </Modal>
  );
}
