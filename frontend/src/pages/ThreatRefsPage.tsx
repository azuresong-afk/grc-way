import {
  CheckCheck,
  ExternalLink,
  Pencil,
  Plus,
  ShieldAlert,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Drawer } from "../components/Drawer";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ErrorAlert, Loading } from "../components/Status";
import { VerifyBadge } from "../components/VerifyBadge";
import { apiGet, apiSend } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ORIGIN_LABELS } from "../lib/classification";
import { formatDateTime, formatNumber } from "../lib/format";
import {
  KIND_TITLES,
  SECTIONS,
  nextChildCode,
  nextIntruderCode,
  type BulkVerifyResult,
  type SectionKey,
  type ThreatItem,
  type ThreatItemDetail,
  type ThreatKind,
  type ThreatRefs,
} from "../lib/threats";

const path = (code: string) => `/refs/threats/${encodeURIComponent(code)}`;

/** Что добавляется из карточки записи: последствие к виду, техника к тактике. */
const CHILD_KIND: Partial<Record<ThreatKind, ThreatKind>> = {
  consequence_type: "consequence",
  tactic: "technique",
};

type FormState =
  | { mode: "edit"; item: ThreatItem }
  | {
      mode: "create";
      kind: ThreatKind;
      parent: ThreatItem | null;
      code: string;
    };

export function ThreatRefsPage() {
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState<ThreatRefs | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [opened, setOpened] = useState<string | null>(null);
  const [form, setForm] = useState<FormState | null>(null);
  const [bulk, setBulk] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const tab = (SECTIONS.find((s) => s.key === params.get("tab"))?.key ??
    "consequences") as SectionKey;
  const section = SECTIONS.find((s) => s.key === tab)!;

  const load = useCallback(() => {
    apiGet<ThreatRefs>("/refs/threats")
      .then((d) => {
        setData(d);
        setError(null);
      })
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  const items = useMemo(() => data?.items ?? [], [data]);
  const byKind = useCallback(
    (k: ThreatKind) => items.filter((i) => i.kind === k),
    [items],
  );
  const children = useCallback(
    (code: string) => items.filter((i) => i.parent_code === code),
    [items],
  );
  const inTab = items.filter((i) =>
    (section.kinds as readonly ThreatKind[]).includes(i.kind),
  );
  const toVerify = inTab.filter((i) => !i.verified);
  const openedItem = items.find((i) => i.code === opened) ?? null;

  const replace = (item: ThreatItem) => {
    load();
    setOpened(item.code);
  };

  const unverifiedIn = (kinds: readonly ThreatKind[]) =>
    kinds.reduce((n, k) => n + (data?.kinds[k]?.unverified ?? 0), 0);

  const row = (i: ThreatItem, extra?: ReactNode) => (
    <tr
      key={i.code}
      className={`clickable${opened === i.code ? " selected" : ""}${i.parent_code ? " row-child" : ""}`}
      onClick={() => setOpened(i.code)}
    >
      <td className="nowrap">
        <button
          type="button"
          className="link-btn"
          onClick={() => setOpened(i.code)}
        >
          <span className="tag">{i.code}</span>
        </button>
      </td>
      <td>
        {i.title}
        {i.description && (
          <div className="cell-sub clamp-2">{i.description}</div>
        )}
      </td>
      {extra}
      <td>
        <VerifyBadge verified={i.verified} />
      </td>
    </tr>
  );

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            <Link to="/refs">Справочники</Link> / Методика оценки угроз
          </div>
          <h1>Методика оценки угроз</h1>
        </div>
        {can("refs.verify") && toVerify.length > 0 && (
          <div className="actions">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => setBulk(true)}
            >
              <CheckCheck size={15} /> Сверить раздел
            </button>
          </div>
        )}
      </div>

      {data && (
        <div className={`alert ${data.unverified ? "alert-warn" : "alert-ok"}`}>
          <span className="alert-text">
            {data.document?.document ??
              "Методика оценки угроз безопасности информации"}
            {data.document?.url && (
              <>
                {" "}
                <a
                  href={data.document.url}
                  target="_blank"
                  rel="noreferrer noopener"
                >
                  Текст документа <ExternalLink size={12} />
                </a>
              </>
            )}
            <br />
            {data.unverified
              ? `Не сверено методистом: ${formatNumber(data.unverified)} из ${formatNumber(data.total)}. Пока запись не сверена, документы с ней получают водяной знак «Проект».`
              : "Все записи сверены методистом."}
          </span>
        </div>
      )}

      <div className="tabs" role="tablist" aria-label="Раздел Методики">
        {SECTIONS.map((s) => (
          <button
            key={s.key}
            type="button"
            role="tab"
            className="tab"
            aria-selected={s.key === tab}
            onClick={() => setParams({ tab: s.key }, { replace: true })}
          >
            {s.title}
            {data && unverifiedIn(s.kinds) > 0 && (
              <span className="count">
                {formatNumber(unverifiedIn(s.kinds))}
              </span>
            )}
          </button>
        ))}
      </div>

      {notice && (
        <div className="alert alert-info" role="status">
          <span className="alert-text">{notice}</span>
        </div>
      )}
      {error && <ErrorAlert message={error} onRetry={load} />}
      {!data && !error && <Loading />}

      {data && data.total === 0 && (
        <section className="card">
          <EmptyState
            icon={<ShieldAlert size={21} />}
            title="Справочник не загружен"
            text="Записи загружаются из reference/threats при старте сервиса."
          />
        </section>
      )}

      {data &&
        data.total > 0 &&
        tab === "consequences" &&
        byKind("consequence_type").map((t) => (
          <section key={t.code} className="card">
            <div className="card-head">
              <h2>
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setOpened(t.code)}
                >
                  <span className="tag">{t.code}</span> {t.title}
                </button>
              </h2>
              <VerifyBadge verified={t.verified} />
            </div>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Код</th>
                    <th>Негативное последствие</th>
                    <th>Сверка</th>
                  </tr>
                </thead>
                <tbody>{children(t.code).map((c) => row(c))}</tbody>
              </table>
            </div>
          </section>
        ))}

      {data && data.total > 0 && tab === "intruders" && (
        <>
          <section className="card">
            <div className="card-head">
              <h2>Уровни возможностей нарушителей</h2>
              <span className="count">{byKind("capability").length}</span>
            </div>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Уровень</th>
                    <th>Возможности</th>
                    <th>Сверка</th>
                  </tr>
                </thead>
                <tbody>{byKind("capability").map((c) => row(c))}</tbody>
              </table>
            </div>
          </section>
          <section className="card">
            <div className="card-head">
              <h2>Виды нарушителей</h2>
              {can("refs.manage") && (
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() =>
                    setForm({
                      mode: "create",
                      kind: "intruder",
                      parent: null,
                      code: nextIntruderCode(items),
                    })
                  }
                >
                  <Plus size={14} /> Добавить
                </button>
              )}
            </div>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Код</th>
                    <th>Вид нарушителя</th>
                    <th>Типовой уровень</th>
                    <th>Категория</th>
                    <th>Сверка</th>
                  </tr>
                </thead>
                <tbody>
                  {byKind("intruder").map((i) =>
                    row(
                      i,
                      <>
                        <td className="nowrap">{i.attrs.capability ?? "—"}</td>
                        <td className="nowrap">{i.attrs.category ?? "—"}</td>
                      </>,
                    ),
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      {data && data.total > 0 && tab === "methods" && (
        <>
          <section className="card">
            <div className="card-head">
              <h2>Виды воздействия на объекты</h2>
              <span className="count">{byKind("impact").length}</span>
            </div>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Код</th>
                    <th>Вид воздействия</th>
                    <th>Сверка</th>
                  </tr>
                </thead>
                <tbody>{byKind("impact").map((i) => row(i))}</tbody>
              </table>
            </div>
          </section>
          <section className="card">
            <div className="card-head">
              <h2>Способы реализации угроз</h2>
              <span className="count">{byKind("method").length}</span>
            </div>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Код</th>
                    <th>Способ</th>
                    <th>Сверка</th>
                  </tr>
                </thead>
                <tbody>{byKind("method").map((i) => row(i))}</tbody>
              </table>
            </div>
          </section>
        </>
      )}

      {data && data.total > 0 && tab === "tactics" && (
        <>
          {data.kinds.technique.total === 0 && (
            <div className="alert alert-info">
              <span className="alert-text">
                Техники приложения 11 не заполнены: текст Методики в проект не
                загружен, а воспроизводить их без текста нельзя. Добавьте
                технику из карточки тактики или загрузите текст Методики.
              </span>
            </div>
          )}
          <section className="card">
            <div className="card-head">
              <h2>Тактики и техники</h2>
              <span className="count">
                {byKind("tactic").length} / {byKind("technique").length}
              </span>
            </div>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Код</th>
                    <th>Наименование</th>
                    <th>Техник</th>
                    <th>Сверка</th>
                  </tr>
                </thead>
                <tbody>
                  {byKind("tactic").flatMap((t) => [
                    row(
                      t,
                      <td className="nowrap">
                        {children(t.code).length || (
                          <span className="muted">нет</span>
                        )}
                      </td>,
                    ),
                    ...children(t.code).map((c) => row(c, <td />)),
                  ])}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      {openedItem && (
        <ItemDrawer
          key={`${openedItem.code}-${openedItem.revision}`}
          item={openedItem}
          parent={items.find((i) => i.code === openedItem.parent_code) ?? null}
          onClose={() => setOpened(null)}
          onChanged={replace}
          onEdit={() => setForm({ mode: "edit", item: openedItem })}
          onAddChild={
            CHILD_KIND[openedItem.kind]
              ? () =>
                  setForm({
                    mode: "create",
                    kind: CHILD_KIND[openedItem.kind]!,
                    parent: openedItem,
                    code: nextChildCode(openedItem.code, items),
                  })
              : undefined
          }
        />
      )}

      {form && data && (
        <ItemForm
          state={form}
          capabilities={byKind("capability")}
          documentSource={
            form.mode === "edit"
              ? form.item.source
              : (form.parent ?? byKind("intruder")[0])?.source
          }
          onClose={() => setForm(null)}
          onSaved={(item) => {
            setForm(null);
            replace(item);
          }}
        />
      )}

      {bulk && (
        <Modal
          title="Сверить раздел"
          onClose={() => setBulk(false)}
          footer={
            <>
              <button
                type="button"
                className="btn"
                onClick={() => setBulk(false)}
              >
                Отмена
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={async () => {
                  setBulk(false);
                  try {
                    const r = await apiSend<BulkVerifyResult>(
                      "POST",
                      "/refs/threats/verify",
                      {
                        items: toVerify.map((i) => ({
                          code: i.code,
                          revision: i.revision,
                        })),
                      },
                    );
                    const skipped = Object.entries(r.skipped);
                    setNotice(
                      `Сверено записей: ${r.verified.length}.` +
                        (skipped.length
                          ? ` Не сверено ${skipped.length}: ${skipped.map(([c, why]) => `${c} — ${why}`).join("; ")}.`
                          : ""),
                    );
                  } catch (e) {
                    setError(
                      e instanceof Error
                        ? e.message
                        : "Не удалось отметить сверку",
                    );
                  }
                  load();
                }}
              >
                <CheckCheck size={15} /> Сверено с текстом
              </button>
            </>
          }
        >
          <p>
            Раздел «{section.title}»: {formatNumber(toVerify.length)}{" "}
            несверенных записей. Отметьте сверку, только если сравнили каждую
            запись с текстом Методики. Свои правки сверить нельзя — они
            останутся несверенными.
          </p>
        </Modal>
      )}
    </>
  );
}

function ItemDrawer({
  item,
  parent,
  onClose,
  onChanged,
  onEdit,
  onAddChild,
}: {
  item: ThreatItem;
  parent: ThreatItem | null;
  onClose: () => void;
  onChanged: (i: ThreatItem) => void;
  onEdit: () => void;
  onAddChild?: () => void;
}) {
  const { can } = useAuth();
  const [detail, setDetail] = useState<ThreatItemDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<ThreatItemDetail>(path(item.code))
      .then(setDetail)
      .catch((e: Error) => setError(e.message));
  }, [item.code, item.revision]);

  async function verify() {
    try {
      onChanged(
        await apiSend<ThreatItem>("POST", `${path(item.code)}/verify`, {
          revision: item.revision,
        }),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "Не удалось отметить сверку");
    }
  }

  const src = item.source;
  const child = CHILD_KIND[item.kind];
  return (
    <Drawer
      title={
        <>
          <span className="tag">{item.code}</span> {item.title}
        </>
      }
      subtitle={`${KIND_TITLES[item.kind]} · ревизия ${item.revision}`}
      onClose={onClose}
      footer={
        <>
          {can("refs.manage") && onAddChild && child && (
            <button type="button" className="btn" onClick={onAddChild}>
              <Plus size={15} />{" "}
              {child === "technique"
                ? "Добавить технику"
                : "Добавить последствие"}
            </button>
          )}
          {can("refs.manage") && (
            <button type="button" className="btn" onClick={onEdit}>
              <Pencil size={15} /> Изменить
            </button>
          )}
          {can("refs.verify") && !item.verified && (
            <button type="button" className="btn btn-primary" onClick={verify}>
              <CheckCheck size={15} /> Сверено
            </button>
          )}
        </>
      }
    >
      {error && <ErrorAlert message={error} />}
      <div className="drawer-section">
        <VerifyBadge verified={item.verified} />
        {item.verified ? (
          <p className="muted">
            Сверил(а) {item.verified_by_name},{" "}
            {formatDateTime(item.verified_at)}
          </p>
        ) : (
          <p className="muted">
            Пока запись не сверена, она отмечается в интерфейсе, а документы с
            ней получают водяной знак «Проект».
          </p>
        )}
      </div>

      <div className="drawer-section">
        {item.description && <p className="prewrap">{item.description}</p>}
        <dl className="props">
          {parent && (
            <>
              <dt>{KIND_TITLES[parent.kind]}</dt>
              <dd>
                <span className="tag">{parent.code}</span> {parent.title}
              </dd>
            </>
          )}
          {item.kind === "intruder" && (
            <>
              <dt>Типовой уровень возможностей</dt>
              <dd>{item.attrs.capability ?? "—"}</dd>
              <dt>Категория</dt>
              <dd>{item.attrs.category ?? "—"}</dd>
            </>
          )}
          <dt>Источник</dt>
          <dd>
            {src.document ?? "—"}
            {src.clause && `, ${src.clause}`}
            {src.appendix && `, приложение ${src.appendix}`}
            {src.note && <div className="cell-sub">{src.note}</div>}
          </dd>
          <dt>Происхождение</dt>
          <dd>{ORIGIN_LABELS[item.origin] ?? item.origin}</dd>
        </dl>
      </div>

      {detail && detail.revisions.length > 0 && (
        <div className="drawer-section">
          <h3>История правок</h3>
          <ul className="history">
            {detail.revisions.map((r) => (
              <li key={r.revision}>
                <span>
                  Ревизия {r.revision} → {r.revision + 1}:{" "}
                  {r.changed_by_name ?? "—"}, {formatDateTime(r.changed_at)}
                </span>
                {r.data.title && r.data.title !== item.title && (
                  <span className="cell-sub">Было: {r.data.title}</span>
                )}
                {r.comment && <span className="cell-sub">{r.comment}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </Drawer>
  );
}

function ItemForm({
  state,
  capabilities,
  documentSource,
  onClose,
  onSaved,
}: {
  state: FormState;
  capabilities: ThreatItem[];
  documentSource?: ThreatItem["source"];
  onClose: () => void;
  onSaved: (i: ThreatItem) => void;
}) {
  const editing = state.mode === "edit" ? state.item : null;
  const kind =
    editing?.kind ?? (state.mode === "create" ? state.kind : "consequence");
  const base = editing?.source ?? {
    document: documentSource?.document,
    url: documentSource?.url,
  };
  const [code, setCode] = useState(
    state.mode === "create" ? state.code : (editing?.code ?? ""),
  );
  const [title, setTitle] = useState(editing?.title ?? "");
  const [description, setDescription] = useState(editing?.description ?? "");
  const [capability, setCapability] = useState(editing?.attrs.capability ?? "");
  const [category, setCategory] = useState(editing?.attrs.category ?? "");
  const [document, setDocument] = useState(base.document ?? "");
  const [clause, setClause] = useState(editing?.source.clause ?? "");
  const [appendix, setAppendix] = useState(
    editing?.source.appendix ?? (kind === "technique" ? "11" : ""),
  );
  const [note, setNote] = useState(editing?.source.note ?? "");
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const attrs =
      kind === "intruder"
        ? Object.fromEntries(
            Object.entries({ capability, category }).filter(([, v]) => v),
          )
        : (editing?.attrs ?? {});
    const source = {
      document: document.trim(),
      url: base.url ?? null,
      clause: clause.trim() || null,
      appendix: appendix.trim() || null,
      note: note.trim() || null,
    };
    const body = {
      title: title.trim(),
      description: description.trim() || null,
      attrs,
      source,
      comment: comment.trim(),
    };
    try {
      onSaved(
        editing
          ? await apiSend<ThreatItem>("PATCH", path(editing.code), body)
          : await apiSend<ThreatItem>("POST", "/refs/threats", {
              ...body,
              kind,
              code: code.trim(),
              parent_code:
                state.mode === "create" ? (state.parent?.code ?? null) : null,
            }),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Не удалось сохранить");
      setBusy(false);
    }
  }

  const heading = editing
    ? `Изменить ${editing.code}`
    : `${KIND_TITLES[kind]}${state.mode === "create" && state.parent ? ` · ${state.parent.code}` : ""}`;

  return (
    <Modal
      title={heading}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button
            type="submit"
            form="threat-form"
            className="btn btn-primary"
            disabled={
              busy ||
              !title.trim() ||
              !comment.trim() ||
              !document.trim() ||
              !code.trim()
            }
          >
            Сохранить
          </button>
        </>
      }
    >
      <form id="threat-form" className="form-stack" onSubmit={submit}>
        {error && <ErrorAlert message={error} />}
        <div className="alert alert-info">
          <span className="alert-text">
            {editing
              ? "После сохранения запись снова потребует сверки методистом."
              : "Новая запись появится как изменённая в интерфейсе и потребует сверки другим методистом."}
          </span>
        </div>
        {!editing && (
          <label className="field">
            <span>Код</span>
            <input
              className="input"
              value={code}
              maxLength={32}
              onChange={(e) => setCode(e.target.value)}
              required
            />
          </label>
        )}
        <label className="field">
          <span>Наименование</span>
          <textarea
            className="textarea"
            rows={2}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            required
          />
          <small>Дословно из текста Методики</small>
        </label>
        <label className="field">
          <span>Описание</span>
          <textarea
            className="textarea"
            rows={3}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </label>
        {kind === "intruder" && (
          <div className="form-row">
            <label className="field">
              <span>Типовой уровень возможностей</span>
              <select
                className="select"
                value={capability}
                onChange={(e) => setCapability(e.target.value)}
              >
                <option value="">не указан</option>
                {capabilities.map((c) => (
                  <option key={c.code} value={c.code}>
                    {c.code}
                  </option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Категория</span>
              <select
                className="select"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
              >
                <option value="">не указана</option>
                <option value="внешний">внешний</option>
                <option value="внутренний">внутренний</option>
              </select>
            </label>
          </div>
        )}
        <label className="field">
          <span>Документ-источник</span>
          <input
            className="input"
            value={document}
            onChange={(e) => setDocument(e.target.value)}
            required
          />
        </label>
        <div className="form-row">
          <label className="field">
            <span>Пункт, таблица</span>
            <input
              className="input"
              value={clause}
              onChange={(e) => setClause(e.target.value)}
            />
          </label>
          <label className="field">
            <span>Приложение</span>
            <input
              className="input"
              value={appendix}
              onChange={(e) => setAppendix(e.target.value)}
            />
          </label>
        </div>
        <label className="field">
          <span>Примечание</span>
          <input
            className="input"
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </label>
        <label className="field">
          <span>Основание правки</span>
          <input
            className="input"
            value={comment}
            maxLength={1000}
            onChange={(e) => setComment(e.target.value)}
            required
          />
          <small>Попадёт в историю правок и журнал аудита</small>
        </label>
      </form>
    </Modal>
  );
}
