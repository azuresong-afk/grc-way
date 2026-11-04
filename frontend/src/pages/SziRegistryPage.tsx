import { AlertTriangle, ArrowLeft, CheckCheck, FileUp, History, Search, ShieldCheck } from "lucide-react";
import { Fragment, useCallback, useEffect, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Drawer } from "../components/Drawer";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { Pager } from "../components/Pager";
import { ErrorAlert, Loading } from "../components/Status";
import { ApiError, apiFetch, apiGet, apiPage, apiSend, query } from "../lib/api";
import { useAuth } from "../lib/auth";
import { CHANGE, IMPORT_STATUS, formatDate, formatSize, plainText, type Change, type Plain } from "../lib/bdu";
import { formatDateTime, formatNumber } from "../lib/format";
import {
  CERT_STATUS,
  type Cert,
  type CertBrief,
  type RegistryStatus,
  type SziImport,
  type SziImportBrief,
} from "../lib/szi";

type Tab = "certs" | "imports";
type Validity = "" | "valid" | "expiring" | "expired" | "withdrawn";
const LIMIT = 50;

function useDebounced(value: string, ms = 300): string {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

function daysLeft(iso: string | null): number | null {
  if (!iso) return null;
  const d = new Date(`${iso}T00:00:00`);
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return Math.round((d.getTime() - today.getTime()) / 86_400_000);
}

export function SziRegistryPage() {
  const { can } = useAuth();
  const canManage = can("refs.manage");
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as Tab | null) ?? "certs";
  const [status, setStatus] = useState<RegistryStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [upload, setUpload] = useState(false);

  const set = (patch: Record<string, string>) =>
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(patch)) {
        if (v) next.set(k, v);
        else next.delete(k);
      }
      return next;
    });

  const loadStatus = useCallback(() => {
    apiGet<RegistryStatus>("/szi-registry/status")
      .then(setStatus)
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(loadStatus, [loadStatus]);

  const pending = status?.pending_id;
  const validity = (params.get("validity") ?? "") as Validity;

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            <Link to="/refs">Справочники</Link>
          </div>
          <h1>Реестр сертифицированных СЗИ</h1>
        </div>
        <div className="actions">
          <Link to="/refs" className="btn btn-ghost">
            <ArrowLeft size={15} /> К справочникам
          </Link>
          {canManage && (
            <button type="button" className="btn btn-primary" onClick={() => setUpload(true)}>
              <FileUp size={15} /> Загрузить реестр
            </button>
          )}
        </div>
      </div>

      {error && <ErrorAlert message={error} onRetry={loadStatus} />}
      {!status && !error && <Loading />}

      {status && (
        <div className="kpi-row">
          <button
            type="button"
            className={`card kpi kpi-btn${tab === "certs" && !validity ? " active" : ""}`}
            onClick={() => set({ tab: "", validity: "", page: "" })}
          >
            <span className="kpi-label">Сертификатов в реестре</span>
            <span className={`kpi-value${status.active ? "" : " muted"}`}>{formatNumber(status.active)}</span>
            <span className="kpi-delta">
              {status.version ? `реестр от ${formatDate(status.version)}` : "ещё не загружался"}
            </span>
          </button>
          <button
            type="button"
            className={`card kpi kpi-btn${validity === "expiring" ? " active" : ""}`}
            onClick={() => set({ tab: "", validity: "expiring", page: "" })}
          >
            <span className="kpi-label">Истекают</span>
            <span className={`kpi-value${status.expiring ? " warn" : " muted"}`}>{formatNumber(status.expiring)}</span>
            <span className="kpi-delta">в ближайшие {status.expiry_days} дн.</span>
          </button>
          <button
            type="button"
            className={`card kpi kpi-btn${validity === "expired" ? " active" : ""}`}
            onClick={() => set({ tab: "", validity: "expired", page: "" })}
          >
            <span className="kpi-label">Срок истёк</span>
            <span className={`kpi-value${status.expired ? "" : " muted"}`}>{formatNumber(status.expired)}</span>
            <span className="kpi-delta">записи реестра с прошедшей датой</span>
          </button>
          <button
            type="button"
            className={`card kpi kpi-btn${validity === "withdrawn" ? " active" : ""}`}
            onClick={() => set({ tab: "", validity: "withdrawn", page: "" })}
          >
            <span className="kpi-label">Исключены</span>
            <span className={`kpi-value${status.withdrawn ? " warn" : " muted"}`}>
              {formatNumber(status.withdrawn)}
            </span>
            <span className="kpi-delta">пропали из последнего реестра</span>
          </button>
        </div>
      )}

      <div className="alert alert-info">
        <span className="alert-text">
          Столбцы реестра распознаются по ключевым словам заголовков; уровень доверия и профили защиты выделяются
          из текста «Наименования документов». <strong>Требует сверки</strong> с актуальным файлом реестра ФСТЭК
          России.
        </span>
      </div>

      {pending && !(tab === "imports" && params.get("import") === pending) && (
        <div className="alert alert-warn">
          <AlertTriangle size={15} />
          <span className="alert-text">
            Есть загруженный реестр, который ещё не применён.{" "}
            <button type="button" className="link-btn" onClick={() => set({ tab: "imports", import: pending })}>
              Открыть сравнение
            </button>
          </span>
        </div>
      )}

      <div className="tabs" role="tablist" aria-label="Раздел реестра СЗИ">
        {(
          [
            ["certs", "Сертификаты"],
            ["imports", "Загрузки"],
          ] as [Tab, string][]
        ).map(([t, label]) => (
          <button
            key={t}
            type="button"
            role="tab"
            className="tab"
            aria-selected={tab === t}
            onClick={() => set({ tab: t === "certs" ? "" : t, import: "", q: "", page: "" })}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "certs" && <CertsTab params={params} set={set} empty={status?.active === 0 && !validity} />}
      {tab === "imports" && (
        <ImportsTab importId={params.get("import")} open={(id) => set({ import: id })} onApplied={loadStatus} />
      )}

      {upload && (
        <UploadModal
          onClose={() => setUpload(false)}
          onDone={(imp) => {
            setUpload(false);
            loadStatus();
            set({ tab: "imports", import: imp.id });
          }}
        />
      )}
    </>
  );
}

function CertsTab({
  params,
  set,
  empty,
}: {
  params: URLSearchParams;
  set: (patch: Record<string, string>) => void;
  empty: boolean;
}) {
  const [q, setQ] = useState(params.get("q") ?? "");
  const dq = useDebounced(q);
  const validity = (params.get("validity") ?? "") as Validity;
  const offset = Number(params.get("page") ?? 0) * LIMIT;
  const [data, setData] = useState<{ items: CertBrief[]; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    setError(null);
    apiPage<CertBrief>(
      `/szi-registry${query({
        q: dq,
        validity: validity === "withdrawn" ? "" : validity,
        withdrawn: validity === "withdrawn" ? "true" : "",
        limit: LIMIT,
        offset,
      })}`,
    )
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [dq, validity, offset]);

  if (empty) {
    return (
      <section className="card">
        <EmptyState
          icon={<ShieldCheck size={21} />}
          title="Реестр не загружен"
          text="Скачайте «Государственный реестр сертифицированных средств защиты информации» на fstec.ru и загрузите его как XLSX или CSV: сначала будет показано сравнение, данные меняются только после «Применить»."
        />
      </section>
    );
  }
  return (
    <>
      <div className="toolbar">
        <label className="search-field">
          <Search size={14} aria-hidden="true" />
          <input
            className="input toolbar-search"
            type="search"
            placeholder="Номер, наименование, заявитель"
            aria-label="Поиск сертификата"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              set({ q: e.target.value, page: "" });
            }}
          />
        </label>
        <div className="chips">
          {(
            [
              ["", "Все действующие"],
              ["expiring", "Истекают"],
              ["expired", "Срок истёк"],
              ["withdrawn", "Исключены"],
            ] as [Validity, string][]
          ).map(([v, label]) => (
            <button
              key={v || "all"}
              type="button"
              className="chip"
              aria-pressed={validity === v}
              onClick={() => set({ validity: v, page: "" })}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      {error && <ErrorAlert message={error} />}
      {!data && !error && <Loading />}
      {data && data.items.length === 0 && (
        <section className="card">
          <EmptyState icon={<CheckCheck size={21} />} title="Ничего не найдено" text="Под выбранные условия сертификатов нет." />
        </section>
      )}
      {data && data.items.length > 0 && (
        <section className="card">
          <div className="table-wrap">
            <table className="table szi-reg-table">
              <thead>
                <tr>
                  <th>№</th>
                  <th>Средство</th>
                  <th>Уровень доверия</th>
                  <th>Действует до</th>
                  <th>Состояние</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((c) => {
                  const days = daysLeft(c.valid_to);
                  return (
                    <tr key={c.cert_number} className="clickable" onClick={() => setOpen(c.cert_number)}>
                      <td className="nowrap">
                        <button type="button" className="link-btn mono" onClick={() => setOpen(c.cert_number)}>
                          {c.cert_number}
                        </button>
                      </td>
                      <td className="bdu-title">
                        {c.name}
                        {c.applicant && <div className="muted small">{c.applicant}</div>}
                      </td>
                      <td>
                        {c.trust_level ? `УД ${c.trust_level}` : <span className="muted">—</span>}
                        {c.profiles.length > 0 && <div className="muted small mono">{c.profiles.join(", ")}</div>}
                      </td>
                      <td className="nowrap">
                        {formatDate(c.valid_to)}
                        {days !== null && days < 0 && <div className="small text-warn">истёк</div>}
                      </td>
                      <td>
                        <div className="pill-stack">
                          {c.withdrawn_at ? (
                            <span className="pill pill-warn">Исключён</span>
                          ) : (
                            <span className={`pill ${CERT_STATUS[c.cert_status][1]}`}>
                              {CERT_STATUS[c.cert_status][0]}
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <Pager total={data.total} limit={LIMIT} offset={offset} onChange={(o) => set({ page: String(o / LIMIT) })} />
        </section>
      )}
      {open && <CertDrawer number={open} onClose={() => setOpen(null)} />}
    </>
  );
}

function Props({ rows }: { rows: [string, ReactNode][] }) {
  return (
    <dl className="props">
      {rows
        .filter(([, v]) => v !== null && v !== undefined && v !== "")
        .map(([k, v]) => (
          <Fragment key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </Fragment>
        ))}
    </dl>
  );
}

function CertDrawer({ number, onClose }: { number: string; onClose: () => void }) {
  const [c, setC] = useState<Cert | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiGet<Cert>(`/szi-registry/${encodeURIComponent(number)}`)
      .then(setC)
      .catch((e: Error) => setError(e.message));
  }, [number]);
  return (
    <Drawer title={<span className="mono">№ {number}</span>} subtitle={c?.name} onClose={onClose}>
      {error && <ErrorAlert message={error} />}
      {!c && !error && <Loading />}
      {c && (
        <section className="drawer-section">
          {c.withdrawn_at && (
            <div className="alert alert-warn">
              <span className="alert-text">Сертификата нет в последнем загруженном реестре.</span>
            </div>
          )}
          <Props
            rows={[
              ["Состояние", <span key="s" className={`pill ${CERT_STATUS[c.cert_status][1]}`}>{CERT_STATUS[c.cert_status][0]}</span>],
              ["Внесён в реестр", formatDate(c.registered_on)],
              ["Действует до", c.valid_to_raw ?? formatDate(c.valid_to)],
              ["Уровень доверия", c.trust_level ? `${c.trust_level} (из текста требований — требует сверки)` : null],
              ["Профили защиты", c.profiles.length ? <span className="mono">{c.profiles.join(", ")}</span> : null],
              ["Требования", c.requirements ? <span className="prewrap">{c.requirements}</span> : null],
              ["Схема сертификации", c.scheme],
              ["Испытательная лаборатория", c.lab],
              ["Орган по сертификации", c.cert_body],
              ["Заявитель", c.applicant],
              ["Реквизиты заявителя", c.applicant_details],
              ["Техническая поддержка", c.support_raw],
              ["Примечание", c.note],
              ["Впервые загружен", `реестр от ${formatDate(c.first_version)}`],
              ["Последнее изменение", `реестр от ${formatDate(c.changed_version)}`],
            ]}
          />
        </section>
      )}
    </Drawer>
  );
}

function UploadModal({ onClose, onDone }: { onClose: () => void; onDone: (imp: SziImport) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [version, setVersion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const form = new FormData();
      form.set("file", file);
      if (version) form.set("export_version", version);
      const res = await apiFetch("/szi-registry/imports", { method: "POST", body: form });
      onDone((await res.json()) as SziImport);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Не удалось загрузить файл");
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Загрузить реестр СЗИ"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" onClick={submit} disabled={!file || busy}>
            {busy ? "Разбираем файл…" : "Сравнить"}
          </button>
        </>
      }
    >
      <p className="muted">
        Государственный реестр сертифицированных средств защиты информации ФСТЭК России в формате XLSX или CSV
        (разделитель «;» или «,», кодировка UTF-8 или Windows-1251). Сначала покажем сравнение с загруженным
        реестром — ничего не меняется до «Применить».
      </p>
      <label className="field">
        <span>Файл XLSX или CSV</span>
        <input
          className="input"
          type="file"
          accept=".xlsx,.csv,text/csv,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
      </label>
      <label className="field">
        <span>Дата реестра</span>
        <input className="input" type="date" value={version} onChange={(e) => setVersion(e.target.value)} />
        <small>Необязательно: если не указать, берётся из заголовка или свойств файла.</small>
      </label>
      {error && <ErrorAlert message={error} />}
    </Modal>
  );
}

function ImportsTab({
  importId,
  open,
  onApplied,
}: {
  importId: string | null;
  open: (id: string) => void;
  onApplied: () => void;
}) {
  const [history, setHistory] = useState<SziImportBrief[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    apiGet<SziImportBrief[]>("/szi-registry/imports?limit=50")
      .then(setHistory)
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(load, [load]);

  return (
    <>
      {error && <ErrorAlert message={error} />}
      {importId && (
        <ImportView
          id={importId}
          onApplied={() => {
            load();
            onApplied();
          }}
        />
      )}
      {history && history.length === 0 && (
        <section className="card">
          <EmptyState icon={<History size={21} />} title="Загрузок ещё не было" text="Загрузите файл реестра: здесь появится сравнение и история загрузок." />
        </section>
      )}
      {history && history.length > 0 && (
        <section className="card">
          <div className="card-head">
            <h2>История загрузок</h2>
          </div>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Загружен</th>
                  <th>Файл</th>
                  <th>Реестр от</th>
                  <th>Разница</th>
                  <th>Статус</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id} className={`clickable${h.id === importId ? " selected" : ""}`} onClick={() => open(h.id)}>
                    <td className="nowrap">
                      <button type="button" className="link-btn" onClick={() => open(h.id)}>
                        {formatDateTime(h.created_at)}
                      </button>
                      <div className="muted small">{h.created_by_name ?? "—"}</div>
                    </td>
                    <td className="mono small">{h.file_name}</td>
                    <td className="nowrap">{formatDate(h.export_version)}</td>
                    <td className="nowrap mono">{diffLine(h)}</td>
                    <td>
                      <span className={`pill ${IMPORT_STATUS[h.status][1]}`}>{IMPORT_STATUS[h.status][0]}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </>
  );
}

function diffLine(h: SziImportBrief): string {
  const s = h.summary;
  if (!s.has_changes) return "без изменений";
  return [
    s.add && `+${formatNumber(s.add)}`,
    s.update + s.restore && `~${formatNumber(s.update + s.restore)}`,
    s.withdraw && `−${formatNumber(s.withdraw)}`,
  ]
    .filter(Boolean)
    .join(" ");
}

type ItemFilter = "all" | "validity" | Change;

function FieldDiff({ fields, titles }: { fields: Record<string, [Plain, Plain]>; titles: Record<string, string> }) {
  return (
    <dl className="diff-fields">
      {Object.entries(fields).map(([f, [before, after]]) => {
        const b = plainText(before, f);
        const a = plainText(after, f);
        return (
          <div key={f}>
            <dt>{titles[f] ?? f}</dt>
            <dd>
              {b && a ? (
                <span className="diff-text">
                  <del className="diff-del">{b}</del>
                  <span className="muted" aria-hidden="true">
                    →
                  </span>
                  <ins className="diff-ins">{a}</ins>
                </span>
              ) : a ? (
                <ins className="diff-ins">{a}</ins>
              ) : (
                <del className="diff-del">{b}</del>
              )}
            </dd>
          </div>
        );
      })}
    </dl>
  );
}

function ImportView({ id, onApplied }: { id: string; onApplied: () => void }) {
  const { can } = useAuth();
  const [imp, setImp] = useState<SziImport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<ItemFilter>("all");
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setImp(null);
    setAck(false);
    setFilter("all");
    apiGet<SziImport>(`/szi-registry/imports/${id}`)
      .then(setImp)
      .catch((e: Error) => setError(e.message));
  }, [id]);

  const apply = async () => {
    setBusy(true);
    setError(null);
    try {
      setImp(await apiSend<SziImport>("POST", `/szi-registry/imports/${id}/apply`, { ack_warnings: ack }));
      onApplied();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (error && !imp) return <ErrorAlert message={error} />;
  if (!imp) return <Loading />;
  const s = imp.summary;
  const items = imp.items.filter((i) =>
    filter === "all" ? true : filter === "validity" ? i.validity : i.change === filter,
  );
  const counts: Record<ItemFilter, number> = {
    all: s.items_total,
    validity: s.validity,
    add: s.add,
    update: s.update,
    withdraw: s.withdraw,
    restore: s.restore,
  };
  const filters: [ItemFilter, string][] = [
    ["validity", "Срок или состояние"],
    ["add", "Новые"],
    ["update", "Изменённые"],
    ["withdraw", "Нет в реестре"],
    ...(s.restore > 0 ? ([["restore", "Возвращённые"]] as [ItemFilter, string][]) : []),
  ];

  return (
    <>
      <section className="card card-pad bdu-import-head">
        <div>
          <h2>
            {imp.file_name} · {formatSize(imp.file_size)}
          </h2>
          <div className="muted">
            Реестр от <b>{formatDate(imp.export_version)}</b> ({imp.version_source_title}) · загружен{" "}
            {formatDateTime(imp.created_at)}, {imp.created_by_name ?? "—"} · сертификатов в файле{" "}
            {formatNumber(s.in_file)}
          </div>
        </div>
        <span className={`pill ${IMPORT_STATUS[imp.status][1]}`}>{IMPORT_STATUS[imp.status][0]}</span>
      </section>

      {imp.status === "applied" && imp.applied && (
        <div className="alert alert-ok">
          <CheckCheck size={15} />
          <span className="alert-text">
            {imp.applied.no_changes
              ? "Данные совпадают с файлом; версия реестра отмечена."
              : `Применён ${formatDateTime(imp.applied_at)}, ${imp.applied_by_name ?? "—"}: новых ${imp.applied.added}, изменено ${imp.applied.updated}, возвращено ${imp.applied.restored}, исключено ${imp.applied.withdrawn}, со сменой срока или состояния ${imp.applied.validity}.`}
          </span>
        </div>
      )}
      {imp.status === "superseded" && (
        <div className="alert alert-warn">
          <span className="alert-text">Есть более новая загрузка реестра — эту применить нельзя.</span>
        </div>
      )}

      <div className="kpi-row diff-kpis">
        {filters.map(([f, label]) => (
          <button
            key={f}
            type="button"
            className={`card kpi kpi-btn${filter === f ? " active" : ""}`}
            aria-pressed={filter === f}
            onClick={() => setFilter(filter === f ? "all" : f)}
          >
            <span className="kpi-label">{label}</span>
            <span className={`kpi-value${f === "validity" && counts[f] ? " warn" : counts[f] ? "" : " muted"}`}>
              {formatNumber(counts[f])}
            </span>
          </button>
        ))}
        <div className="card kpi">
          <span className="kpi-label">Без изменений</span>
          <span className="kpi-value muted">{formatNumber(s.unchanged)}</span>
        </div>
      </div>

      {imp.warnings.length > 0 && (
        <div className="alert alert-warn">
          <AlertTriangle size={15} />
          <span className="alert-text">
            <ul className="plain-list">
              {imp.warnings.map((w) => (
                <li key={w.code}>{w.text}</li>
              ))}
            </ul>
          </span>
        </div>
      )}

      {imp.items.length > 0 && (
        <section className="card">
          <div className="card-head">
            <h2>Изменения</h2>
            <span className="count">
              {s.items_shown < s.items_total
                ? `показано ${formatNumber(s.items_shown)} из ${formatNumber(s.items_total)}`
                : formatNumber(s.items_total)}
            </span>
          </div>
          <div className="table-wrap">
            <table className="table diff-table">
              <thead>
                <tr>
                  <th>№</th>
                  <th>Средство</th>
                  <th>Что меняется</th>
                  <th>Отметки</th>
                </tr>
              </thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.key}>
                    <td className="nowrap mono">{i.key}</td>
                    <td className="diff-title">{i.title ?? "—"}</td>
                    <td className="diff-change">
                      {i.fields && Object.keys(i.fields).length > 0 ? (
                        <FieldDiff fields={i.fields} titles={imp.field_titles} />
                      ) : i.change === "add" ? (
                        <span className="nowrap">
                          до {formatDate(i.valid_to ?? null)}
                          {i.trust_level ? ` · УД ${i.trust_level}` : ""}
                        </span>
                      ) : i.change === "withdraw" ? (
                        <span className="muted">
                          Нет в реестре. Запись не удаляется, а помечается исключённой — СЗИ объектов с этим
                          номером получат предупреждение.
                        </span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td>
                      <div className="pill-stack">
                        <span className={`pill ${CHANGE[i.change][1]}`}>{CHANGE[i.change][0]}</span>
                        {i.validity && <span className="pill pill-warn">Срок или состояние</span>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {imp.status === "pending" && can("refs.manage") && (
        <div className="apply-bar">
          {imp.warnings.length > 0 ? (
            <label className="check-inline">
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              Предупреждения прочитаны, применить всё равно
            </label>
          ) : (
            <span>
              {s.has_changes
                ? `Новых ${formatNumber(s.add)}, изменённых ${formatNumber(s.update + s.restore)}, исключённых ${formatNumber(s.withdraw)}`
                : "Изменений нет"}
            </span>
          )}
          {error && <span className="error-text">{error}</span>}
          <button
            type="button"
            className="btn btn-primary"
            onClick={apply}
            disabled={busy || (imp.warnings.length > 0 && !ack)}
          >
            {busy ? "Применяем…" : "Применить реестр"}
          </button>
        </div>
      )}
    </>
  );
}
