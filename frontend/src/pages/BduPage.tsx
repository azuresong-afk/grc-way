import { AlertTriangle, ArrowLeft, Bug, CheckCheck, FileUp, History, Search, ShieldAlert } from "lucide-react";
import { Fragment, useCallback, useEffect, useState, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Drawer } from "../components/Drawer";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { Pager } from "../components/Pager";
import { ErrorAlert, Loading } from "../components/Status";
import { ApiError, apiFetch, apiGet, apiPage, apiSend, query } from "../lib/api";
import { useAuth } from "../lib/auth";
import {
  CHANGE,
  EXPLOIT,
  E_LEVEL,
  IMPORT_STATUS,
  IN_WILD,
  formatDate,
  formatSize,
  plainText,
  type BduKind,
  type BduStatus,
  type Change,
  type Import,
  type ImportBrief,
  type Plain,
  type Threat,
  type Vuln,
  type VulnBrief,
} from "../lib/bdu";
import { formatDateTime, formatNumber } from "../lib/format";

type Tab = "vulns" | "threats" | "imports";
const TABS: [Tab, string][] = [
  ["vulns", "Уязвимости"],
  ["threats", "Угрозы (УБИ)"],
  ["imports", "Загрузки"],
];
const LIMIT = 50;

function Pill({ map, value }: { map: Record<string, [string, string]>; value: string | null }) {
  if (!value) return <span className="muted">—</span>;
  const [label, cls] = map[value] ?? [value, "pill-muted"];
  return <span className={`pill ${cls}`}>{label}</span>;
}

function Score({ v }: { v: Pick<VulnBrief, "cvss3_score" | "cvss3_version" | "cvss3_score_source"> }) {
  if (v.cvss3_score === null) return <span className="muted">нет 3.x</span>;
  return (
    <span className="nowrap">
      <b className="mono">{v.cvss3_score.toFixed(1).replace(".", ",")}</b>{" "}
      <span className="muted">
        {v.cvss3_version}
        {v.cvss3_score_source === "computed" ? " · расчёт" : ""}
      </span>
    </span>
  );
}

function FieldDiff({ fields, titles }: { fields: Record<string, [Plain, Plain]>; titles: Record<string, string> }) {
  return (
    <dl className="diff-fields">
      {Object.entries(fields)
        // Текст БДУ дублирует нормализованное значение, если оно тоже изменилось.
        .filter(([f]) => !(f.endsWith("_raw") && f.slice(0, -4) in fields))
        .map(([f, [before, after]]) => {
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

export function BduPage() {
  const { can } = useAuth();
  const canManage = can("refs.manage");
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as Tab | null) ?? "vulns";
  const [status, setStatus] = useState<BduStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [upload, setUpload] = useState(false);

  const set = (patch: Record<string, string>) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        for (const [k, v] of Object.entries(patch)) {
          if (v) next.set(k, v);
          else next.delete(k);
        }
        return next;
      },
      { replace: false },
    );

  const loadStatus = useCallback(() => {
    apiGet<BduStatus>("/bdu/status")
      .then(setStatus)
      .catch((e: Error) => setError(e.message));
  }, []);
  useEffect(loadStatus, [loadStatus]);

  const pending = status && (status.vulns.pending_id ?? status.threats.pending_id);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            <Link to="/refs">Справочники</Link>
          </div>
          <h1>БДУ ФСТЭК России</h1>
        </div>
        <div className="actions">
          <Link to="/refs" className="btn btn-ghost">
            <ArrowLeft size={15} /> К справочникам
          </Link>
          {canManage && (
            <button type="button" className="btn btn-primary" onClick={() => setUpload(true)}>
              <FileUp size={15} /> Загрузить выгрузку
            </button>
          )}
        </div>
      </div>

      {error && <ErrorAlert message={error} onRetry={loadStatus} />}
      {!status && !error && <Loading />}

      {status && (
        <div className="kpi-row bdu-kpis">
          {(["vulns", "threats"] as BduKind[]).map((k) => {
            const s = status[k];
            return (
              <button
                key={k}
                type="button"
                className={`card kpi kpi-btn${tab === k ? " active" : ""}`}
                onClick={() => set({ tab: k, import: "" })}
              >
                <span className="kpi-label">
                  {s.title} · <span className="mono">{s.file_name}</span>
                </span>
                <span className={`kpi-value${s.active ? "" : " muted"}`}>{formatNumber(s.active)}</span>
                <span className="kpi-delta">
                  {s.version ? `выгрузка от ${formatDate(s.version)}` : "ещё не загружалась"}
                  {s.withdrawn > 0 && ` · исключено ${formatNumber(s.withdrawn)}`}
                </span>
              </button>
            );
          })}
          <div className="card kpi">
            <span className="kpi-label">Требуют пересчёта критичности</span>
            <span className={`kpi-value${status.vulns.criticality_last ? " warn" : " muted"}`}>
              {formatNumber(status.vulns.criticality_last ?? 0)}
            </span>
            <span className="kpi-delta">в последней выгрузке уязвимостей</span>
          </div>
        </div>
      )}

      {pending && !(tab === "imports" && params.get("import") === pending) && (
        <div className="alert alert-warn">
          <AlertTriangle size={15} />
          <span className="alert-text">
            Есть загруженная выгрузка, которая ещё не применена.{" "}
            <button type="button" className="link-btn" onClick={() => set({ tab: "imports", import: pending })}>
              Открыть сравнение
            </button>
          </span>
        </div>
      )}

      <div className="tabs" role="tablist" aria-label="Раздел БДУ">
        {TABS.map(([t, label]) => (
          <button
            key={t}
            type="button"
            role="tab"
            className="tab"
            aria-selected={tab === t}
            onClick={() => set({ tab: t, import: "", q: "", page: "" })}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "vulns" && <VulnsTab params={params} set={set} empty={status?.vulns.active === 0} />}
      {tab === "threats" && <ThreatsTab params={params} set={set} empty={status?.threats.active === 0} />}
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

interface TabProps {
  params: URLSearchParams;
  set: (patch: Record<string, string>) => void;
  empty?: boolean;
}

function useDebounced(value: string, ms = 300): string {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

function NotLoaded({ kind }: { kind: BduKind }) {
  return (
    <section className="card">
      <EmptyState
        icon={kind === "vulns" ? <Bug size={21} /> : <ShieldAlert size={21} />}
        title={kind === "vulns" ? "Уязвимости не загружены" : "Угрозы не загружены"}
        text={`Скачайте ${kind === "vulns" ? "vullist.xlsx" : "thrlist.xlsx"} на bdu.fstec.ru и загрузите его здесь: сначала будет показано сравнение, данные меняются только после «Применить».`}
      />
    </section>
  );
}

function VulnsTab({ params, set, empty }: TabProps) {
  const [q, setQ] = useState(params.get("q") ?? "");
  const dq = useDebounced(q);
  const exploit = params.get("exploit") ?? "";
  const inWild = params.get("in_wild") ?? "";
  const crit = params.get("crit") === "1";
  const offset = Number(params.get("page") ?? 0) * LIMIT;
  const [data, setData] = useState<{ items: VulnBrief[]; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    setError(null);
    apiPage<VulnBrief>(
      `/bdu/vulns${query({ q: dq, exploit, in_wild: inWild, crit_changed: crit ? "true" : "", limit: LIMIT, offset })}`,
    )
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [dq, exploit, inWild, crit, offset]);

  if (empty) return <NotLoaded kind="vulns" />;
  return (
    <>
      <div className="toolbar">
        <label className="search-field">
          <Search size={14} aria-hidden="true" />
          <input
            className="input toolbar-search"
            type="search"
            placeholder="BDU, CVE, ПО или наименование"
            aria-label="Поиск уязвимости"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              set({ q: e.target.value, page: "" });
            }}
          />
        </label>
        <select
          className="select toolbar-select"
          aria-label="Наличие эксплойта"
          value={exploit}
          onChange={(e) => set({ exploit: e.target.value, page: "" })}
        >
          <option value="">Эксплойт: любой</option>
          {Object.entries(EXPLOIT).map(([k, [label]]) => (
            <option key={k} value={k}>
              {label}
            </option>
          ))}
        </select>
        <select
          className="select toolbar-select"
          aria-label="Эксплуатация в реальных атаках"
          value={inWild}
          onChange={(e) => set({ in_wild: e.target.value, page: "" })}
        >
          <option value="">Эксплуатация: любая</option>
          {Object.entries(IN_WILD).map(([k, [label]]) => (
            <option key={k} value={k}>
              {label}
            </option>
          ))}
        </select>
        <div className="chips">
          <button
            type="button"
            className="chip"
            aria-pressed={crit}
            onClick={() => set({ crit: crit ? "" : "1", page: "" })}
          >
            Изменились сведения для критичности
          </button>
        </div>
      </div>

      {error && <ErrorAlert message={error} />}
      {!data && !error && <Loading />}
      {data && data.items.length === 0 && (
        <section className="card">
          <EmptyState icon={<CheckCheck size={21} />} title="Ничего не найдено" text="Под выбранные фильтры уязвимостей нет." />
        </section>
      )}
      {data && data.items.length > 0 && (
        <section className="card">
          <div className="table-wrap">
            <table className="table bdu-table">
              <thead>
                <tr>
                  <th>Идентификатор</th>
                  <th>Уязвимость</th>
                  <th>CVSS 3.x</th>
                  <th>Эксплойт</th>
                  <th>Эксплуатация в атаках</th>
                  <th>Изменена</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((v) => (
                  <tr key={v.bdu_id} className="clickable" onClick={() => setOpen(v.bdu_id)}>
                    <td className="nowrap">
                      <button type="button" className="link-btn tag" onClick={() => setOpen(v.bdu_id)}>
                        {v.bdu_id}
                      </button>
                      {v.cve_ids.length > 0 && <div className="muted mono small">{v.cve_ids.join(", ")}</div>}
                    </td>
                    <td className="bdu-title">
                      {v.title}
                      {(v.vendor || v.product) && (
                        <div className="muted small">{[v.vendor, v.product].filter(Boolean).join(" · ")}</div>
                      )}
                    </td>
                    <td>
                      <Score v={v} />
                    </td>
                    <td>
                      <Pill map={EXPLOIT} value={v.exploit} />
                    </td>
                    <td>
                      <Pill map={IN_WILD} value={v.in_wild} />
                    </td>
                    <td className="nowrap">
                      {formatDate(v.changed_version)}
                      {v.criticality_changed_at && (
                        <div>
                          <span className="pill pill-warn">Пересчитать</span>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager total={data.total} limit={LIMIT} offset={offset} onChange={(o) => set({ page: String(o / LIMIT) })} />
        </section>
      )}
      {open && <VulnDrawer id={open} onClose={() => setOpen(null)} />}
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

const CRIT_TITLES: Record<string, string> = {
  cvss3_vector: "Вектор CVSS 3.x",
  cvss3_score: "Оценка CVSS 3.x",
  exploit: "Наличие эксплойта",
  in_wild: "Эксплуатация в реальных атаках",
  status: "Статус уязвимости",
};

function VulnDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const [v, setV] = useState<Vuln | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiGet<Vuln>(`/bdu/vulns/${encodeURIComponent(id)}`)
      .then(setV)
      .catch((e: Error) => setError(e.message));
  }, [id]);
  return (
    <Drawer title={<span className="tag">{id}</span>} subtitle={v?.title} onClose={onClose}>
      {error && <ErrorAlert message={error} />}
      {!v && !error && <Loading />}
      {v && (
        <>
          {v.criticality_changed_at && v.criticality_changes && (
            <div className="alert alert-warn">
              <AlertTriangle size={15} />
              <span className="alert-text">
                В выгрузке от {formatDate(v.criticality_changed_version)} изменились сведения, от которых зависит
                уровень критичности. Оценки, сделанные раньше, нужно пересчитать (Методика ФСТЭК 30.06.2025, п. 16,
                19).
                <FieldDiff fields={v.criticality_changes} titles={CRIT_TITLES} />
              </span>
            </div>
          )}
          {v.withdrawn_at && (
            <div className="alert alert-warn">
              <span className="alert-text">Уязвимости нет в последней выгрузке БДУ ({formatDateTime(v.withdrawn_at)}).</span>
            </div>
          )}
          <section className="drawer-section">
            <h3>Для оценки критичности</h3>
            <Props
              rows={[
                ["CVSS 3.x", <Score key="s" v={v} />],
                ["Вектор", v.cvss3_vector && <span className="mono">{v.cvss3_vector}</span>],
                ["Уровень опасности", v.severity && <span className="prewrap">{v.severity}</span>],
                [
                  "Другие версии CVSS",
                  v.cvss_other &&
                    Object.entries(v.cvss_other)
                      .map(([k, o]) => `${k === "cvss2" ? "2.0" : "4.0"}: ${o?.score ?? "—"} ${o?.vector ?? ""}`)
                      .join("; "),
                ],
                ["Наличие эксплойта", <span key="e">{v.exploit_raw ?? "—"}</span>],
                ["Эксплуатация в атаках", <span key="w">{v.in_wild_raw ?? "—"}</span>],
                ["Показатель E по БДУ", E_LEVEL[v.e_level]],
                ["Статус", v.status],
              ]}
            />
            <p className="muted small">
              Показатель E окончательно выбирает специалист при оценке; если сведений несколько, берётся наибольшее
              значение (п. 16).
            </p>
          </section>
          <section className="drawer-section">
            <h3>Описание</h3>
            <p className="prewrap">{v.description ?? "—"}</p>
            <Props
              rows={[
                ["Вендор", v.vendor],
                ["ПО", v.product],
                ["Версия", v.product_version],
                ["Тип ПО", v.sw_type],
                ["ОС и платформа", v.platform],
                ["Класс", v.vuln_class],
                ["Выявлена", v.identified_on && formatDate(v.identified_on)],
                ["CVE", v.cve_ids.join(", ")],
                ["CWE", v.cwe_ids.join(", ")],
                ["Способ эксплуатации", v.exploit_method],
                ["Меры по устранению", v.measures],
                ["Способ устранения", v.fix_method],
                ["Информация об устранении", v.fix_info],
                ["Ссылки", v.links && <span className="prewrap small">{v.links}</span>],
              ]}
            />
          </section>
          <section className="drawer-section">
            <h3>Версии выгрузки</h3>
            <Props
              rows={[
                ["Впервые загружена", formatDate(v.first_version)],
                ["Последнее изменение", formatDate(v.changed_version)],
              ]}
            />
          </section>
        </>
      )}
    </Drawer>
  );
}

function Cia({ t }: { t: Threat }) {
  const marks: [boolean | null, string, string][] = [
    [t.conf, "К", "конфиденциальность"],
    [t.integ, "Ц", "целостность"],
    [t.avail, "Д", "доступность"],
  ];
  return (
    <span className="cia">
      {marks.map(([on, l, title]) => (
        <span key={l} className={`cia-mark${on ? " on" : ""}`} title={`${on ? "Нарушается" : "Не нарушается"} ${title}`}>
          {l}
        </span>
      ))}
    </span>
  );
}

function ThreatsTab({ params, set, empty }: TabProps) {
  const [q, setQ] = useState(params.get("q") ?? "");
  const dq = useDebounced(q);
  const offset = Number(params.get("page") ?? 0) * LIMIT;
  const [data, setData] = useState<{ items: Threat[]; total: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<Threat | null>(null);

  useEffect(() => {
    apiPage<Threat>(`/bdu/threats${query({ q: dq, limit: LIMIT, offset })}`)
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [dq, offset]);

  if (empty) return <NotLoaded kind="threats" />;
  return (
    <>
      <div className="toolbar">
        <label className="search-field">
          <Search size={14} aria-hidden="true" />
          <input
            className="input toolbar-search"
            type="search"
            placeholder="Номер УБИ или наименование"
            aria-label="Поиск угрозы"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              set({ q: e.target.value, page: "" });
            }}
          />
        </label>
      </div>
      {error && <ErrorAlert message={error} />}
      {!data && !error && <Loading />}
      {data && data.items.length === 0 && (
        <section className="card">
          <EmptyState icon={<CheckCheck size={21} />} title="Ничего не найдено" text="Под запрос угроз нет." />
        </section>
      )}
      {data && data.items.length > 0 && (
        <section className="card">
          <div className="table-wrap">
            <table className="table bdu-table">
              <thead>
                <tr>
                  <th>УБИ</th>
                  <th>Наименование</th>
                  <th>Нарушает</th>
                  <th>Изменена в БДУ</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((t) => (
                  <tr key={t.code} className="clickable" onClick={() => setOpen(t)}>
                    <td className="nowrap">
                      <button type="button" className="link-btn tag" onClick={() => setOpen(t)}>
                        {t.code}
                      </button>
                    </td>
                    <td className="bdu-title">{t.title}</td>
                    <td>
                      <Cia t={t} />
                    </td>
                    <td className="nowrap">{formatDate(t.changed_on)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager total={data.total} limit={LIMIT} offset={offset} onChange={(o) => set({ page: String(o / LIMIT) })} />
        </section>
      )}
      {open && (
        <Drawer title={<span className="tag">{open.code}</span>} subtitle={open.title} onClose={() => setOpen(null)}>
          <section className="drawer-section">
            <p className="prewrap">{open.description ?? "—"}</p>
            <Props
              rows={[
                ["Источник угрозы", open.source],
                ["Объект воздействия", open.target],
                ["Нарушает", <Cia key="c" t={open} />],
                ["Включена в БДУ", formatDate(open.published_on)],
                ["Изменена в БДУ", formatDate(open.changed_on)],
                ["Статус", open.status],
                ["Впервые загружена", `выгрузка от ${formatDate(open.first_version)}`],
                ["Последнее изменение", `выгрузка от ${formatDate(open.changed_version)}`],
              ]}
            />
          </section>
        </Drawer>
      )}
    </>
  );
}

function UploadModal({ onClose, onDone }: { onClose: () => void; onDone: (imp: Import) => void }) {
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
      const res = await apiFetch("/bdu/imports", { method: "POST", body: form });
      onDone((await res.json()) as Import);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Не удалось загрузить файл");
      setBusy(false);
    }
  };

  return (
    <Modal
      title="Загрузить выгрузку БДУ"
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
        Файлы со страницы bdu.fstec.ru: перечень угроз <span className="mono">thrlist.xlsx</span> или перечень
        уязвимостей <span className="mono">vullist.xlsx</span>. Вид определяется по заголовкам. Сначала покажем
        сравнение с загруженными данными — ничего не меняется до «Применить».
      </p>
      <label className="field">
        <span>Файл XLSX</span>
        <input
          className="input"
          type="file"
          accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
      </label>
      <label className="field">
        <span>Дата выгрузки</span>
        <input className="input" type="date" value={version} onChange={(e) => setVersion(e.target.value)} />
        <small>Необязательно: если не указать, берётся из файла.</small>
      </label>
      {busy && <p className="muted small">Перечень уязвимостей — около 100 тысяч строк, разбор занимает до минуты.</p>}
      {error && <ErrorAlert message={error} />}
    </Modal>
  );
}

type ItemFilter = "all" | "criticality" | Change;
const ITEM_FILTERS: [ItemFilter, string][] = [
  ["all", "Все"],
  ["criticality", "Критичные"],
  ["add", "Новые"],
  ["update", "Изменённые"],
  ["withdraw", "Нет в выгрузке"],
  ["restore", "Возвращённые"],
];

function ImportsTab({
  importId,
  open,
  onApplied,
}: {
  importId: string | null;
  open: (id: string) => void;
  onApplied: () => void;
}) {
  const [history, setHistory] = useState<ImportBrief[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    apiGet<ImportBrief[]>("/bdu/imports?limit=50")
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
          <EmptyState
            icon={<History size={21} />}
            title="Загрузок ещё не было"
            text="Загрузите thrlist.xlsx или vullist.xlsx: здесь появится сравнение и история загрузок."
          />
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
                  <th>Загружена</th>
                  <th>Перечень</th>
                  <th>Выгрузка от</th>
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
                    <td>
                      {h.kind === "vulns" ? "Уязвимости" : "Угрозы"}{" "}
                      <span className="muted mono small">{h.file_name}</span>
                    </td>
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

function diffLine(h: ImportBrief): string {
  const s = h.summary;
  if (!s.has_changes) return "без изменений";
  return [
    s.add && `+${formatNumber(s.add)}`,
    s.update + s.restore && `~${formatNumber(s.update + s.restore)}`,
    s.withdraw && `−${formatNumber(s.withdraw)}`,
    s.criticality && `! ${formatNumber(s.criticality)}`,
  ]
    .filter(Boolean)
    .join(" ");
}

function ImportView({ id, onApplied }: { id: string; onApplied: () => void }) {
  const { can } = useAuth();
  const [imp, setImp] = useState<Import | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<ItemFilter>("all");
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setImp(null);
    setAck(false);
    setFilter("all");
    apiGet<Import>(`/bdu/imports/${id}`)
      .then(setImp)
      .catch((e: Error) => setError(e.message));
  }, [id]);

  const apply = async () => {
    setBusy(true);
    setError(null);
    try {
      setImp(await apiSend<Import>("POST", `/bdu/imports/${id}/apply`, { ack_warnings: ack }));
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
  const vulns = imp.kind === "vulns";
  const items = imp.items.filter((i) =>
    filter === "all" ? true : filter === "criticality" ? i.criticality : i.change === filter,
  );
  const counts: Record<ItemFilter, number> = {
    all: s.items_total,
    criticality: s.criticality,
    add: s.add,
    update: s.update,
    withdraw: s.withdraw,
    restore: s.restore,
  };
  const head = `${vulns ? "Перечень уязвимостей" : "Перечень угроз"} · ${imp.file_name} · ${formatSize(imp.file_size)}`;

  return (
    <>
      <section className="card card-pad bdu-import-head">
        <div>
          <h2>{head}</h2>
          <div className="muted">
            Выгрузка от <b>{formatDate(imp.export_version)}</b> ({imp.version_source_title}) · загружена{" "}
            {formatDateTime(imp.created_at)}, {imp.created_by_name ?? "—"} · записей в файле{" "}
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
              ? "Данные совпадают с выгрузкой; версия выгрузки отмечена."
              : `Применено ${formatDateTime(imp.applied_at)}, ${imp.applied_by_name ?? "—"}: новых ${imp.applied.added}, изменено ${imp.applied.updated}, возвращено ${imp.applied.restored}, исключено ${imp.applied.withdrawn}${vulns ? `, требуют пересчёта критичности ${imp.applied.criticality}` : ""}.`}
          </span>
        </div>
      )}
      {imp.status === "superseded" && (
        <div className="alert alert-warn">
          <span className="alert-text">Есть более новая загрузка этого перечня — эту применить нельзя.</span>
        </div>
      )}

      <div className="kpi-row diff-kpis">
        {ITEM_FILTERS.slice(1)
          .filter(([f]) => (f !== "criticality" || vulns) && (f !== "restore" || s.restore > 0))
          .map(([f, label]) => (
          <button
            key={f}
            type="button"
            className={`card kpi kpi-btn${filter === f ? " active" : ""}`}
            aria-pressed={filter === f}
            onClick={() => setFilter(filter === f ? "all" : f)}
          >
            <span className="kpi-label">{f === "criticality" ? "Критичные изменения" : label}</span>
            <span className={`kpi-value${f === "criticality" && counts[f] ? " warn" : counts[f] ? "" : " muted"}`}>
              {formatNumber(counts[f])}
            </span>
          </button>
        ))}
        <div className="card kpi">
          <span className="kpi-label">Без изменений</span>
          <span className="kpi-value muted">{formatNumber(s.unchanged)}</span>
        </div>
      </div>

      {vulns && s.criticality > 0 && (
        <div className="alert alert-info">
          <AlertTriangle size={15} />
          <span className="alert-text">
            У {formatNumber(s.criticality)} уязвимостей изменились CVSS, наличие эксплойта, сведения об эксплуатации
            или статус. После применения они будут отмечены: оценки уровня критичности по ним нужно пересчитать
            (Методика ФСТЭК 30.06.2025, п. 16, 19).
          </span>
        </div>
      )}

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
                  <th>{vulns ? "Уязвимость" : "УБИ"}</th>
                  <th>Наименование</th>
                  <th>Что меняется</th>
                  <th>Отметки</th>
                </tr>
              </thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.key}>
                    <td className="nowrap">
                      <span className="tag">{i.key}</span>
                    </td>
                    <td className="diff-title">{i.title ?? "—"}</td>
                    <td className="diff-change">
                      {i.fields && Object.keys(i.fields).length > 0 ? (
                        <FieldDiff fields={i.fields} titles={imp.field_titles} />
                      ) : i.change === "add" && vulns ? (
                        <span className="nowrap">
                          {i.cvss3_score != null ? `CVSS ${String(i.cvss3_score).replace(".", ",")}` : "без CVSS 3.x"}{" "}
                          <Pill map={EXPLOIT} value={i.exploit ?? null} />{" "}
                          {i.in_wild === "yes" && <Pill map={IN_WILD} value="yes" />}
                        </span>
                      ) : i.change === "withdraw" ? (
                        <span className="muted">Нет в выгрузке. Запись не удаляется, а помечается исключённой.</span>
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td>
                      <div className="pill-stack">
                        <span className={`pill ${CHANGE[i.change][1]}`}>{CHANGE[i.change][0]}</span>
                        {i.criticality && <span className="pill pill-warn">Пересчитать критичность</span>}
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
            {busy ? "Применяем…" : "Применить выгрузку"}
          </button>
        </div>
      )}
    </>
  );
}
