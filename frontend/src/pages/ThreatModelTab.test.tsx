import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import type { ObjectFull } from "../lib/objects";
import type { FindingRow, FindingsList, ModelDetail, ModelThreat, Progress } from "../lib/threatModel";
import type { ThreatItem, ThreatRefs } from "../lib/threats";
import { fakeApi, json } from "../test/fakeApi";

const METH = {
  id: "u2",
  username: "meth",
  display_name: "Иванова А. А.",
  roles: ["methodologist"],
  permissions: ["view", "objects.edit", "threats.edit"],
};
const BOSS = {
  id: "u9",
  username: "boss",
  display_name: "Смирнов С. С.",
  roles: ["viewer", "approve"],
  permissions: ["view", "approve"],
};

const PROJECT = {
  id: "p1",
  customer_id: "c1",
  client: "ГБУ «Центр»",
  name: "Аттестация ГИС",
  contract_ref: null,
  period_from: null,
  period_to: null,
  status: "active",
  scanner_engagement_id: null,
  platform_project_id: null,
  created_at: "2026-11-01T10:00:00Z",
  members: [],
};

const OBJ: ObjectFull = {
  id: "o1",
  project_id: "p1",
  kind: "gis",
  name: "ГИС «Учёт»",
  regime: "117",
  status: "active",
  internet: true,
  host_count: 1,
  segment_count: 0,
  updated_at: "2026-11-04T10:00:00Z",
  purpose: null,
  boundaries: null,
  interconnections: [],
  responsible: [],
  created_at: "2026-11-04T10:00:00Z",
  scanner_synced_at: null,
  scanner_engagement_id: null,
  segments: [],
  classification: null,
};

function ref(code: string, kind: ThreatItem["kind"], title: string, extra: Partial<ThreatItem> = {}): ThreatItem {
  return {
    code,
    kind,
    parent_code: null,
    position: 0,
    title,
    description: null,
    attrs: {},
    source: { document: "Методика оценки угроз" },
    origin: "stub",
    revision: 1,
    verified: false,
    verified_by_name: null,
    verified_at: null,
    updated_at: "2026-11-04T10:00:00Z",
    ...extra,
  };
}

const REF_ITEMS = [
  ref("У1", "consequence_type", "Ущерб физическому лицу"),
  ref("У1.9", "consequence", "Нарушение конфиденциальности (утечка) персональных данных", { parent_code: "У1" }),
  ref("Н1", "capability", "Базовые возможности"),
  ref("НВ4", "intruder", "Отдельные физические лица (хакеры)", { attrs: { capability: "Н1", category: "внешний" } }),
  ref("НВ11", "intruder", "Авторизованные пользователи", { attrs: { capability: "Н1", category: "внутренний" } }),
  ref("Т2", "tactic", "Получение первоначального доступа"),
  ref("ВВ1", "impact", "Утечка (перехват) конфиденциальной информации"),
  ref("СР1", "method", "Использование уязвимостей"),
];
const REFS: ThreatRefs = {
  document: null,
  total: REF_ITEMS.length,
  unverified: REF_ITEMS.length,
  kinds: {} as ThreatRefs["kinds"],
  items: REF_ITEMS,
};

const STEPS_DONE: Progress = {
  steps: [
    { key: "consequences", title: "Негативные последствия", done: true, count: 1, problems: [], warnings: [] },
    { key: "objects", title: "Объекты воздействия", done: true, count: 1, problems: [], warnings: [] },
    { key: "intruders", title: "Нарушители", done: true, count: 1, problems: [], warnings: [] },
    { key: "methods", title: "Способы и интерфейсы", done: true, count: 1, problems: [], warnings: [] },
    { key: "scenarios", title: "Сценарии", done: true, count: 1, problems: [], warnings: [] },
    { key: "threats", title: "Угрозы БДУ", done: true, count: 1, problems: [], warnings: [] },
  ],
  done: 6,
  total: 6,
  ready: true,
};

const THREAT: ModelThreat = {
  code: "УБИ.006",
  title: "Угроза внедрения кода или данных",
  description: null,
  source: "Внешний нарушитель с низким потенциалом",
  target: "Прикладное ПО",
  conf: true,
  integ: true,
  avail: false,
  withdrawn: false,
  in_bdu: true,
  hint: { categories: ["внешний"], potentials: ["низкий"] },
  relevant: null,
  justification: null,
  intruders: [],
  objects: [],
  consequences: [],
  methods: [],
  tactics: [],
  linked_findings: [],
  confirmed: 0,
  updated_at: "2026-11-04T11:00:00Z",
  updated_by_name: "Иванова А. А.",
};

const MODEL: ModelDetail = {
  id: "m1",
  object_id: "o1",
  version: 1,
  status: "draft",
  based_on: null,
  created_at: "2026-11-04T11:00:00Z",
  created_by: "u2",
  created_by_name: "Иванова А. А.",
  editor_ids: ["u2"],
  edits: 7,
  updated_at: "2026-11-04T11:00:00Z",
  approved_at: null,
  approved_by_name: null,
  approval_comment: null,
  unverified_acknowledged: false,
  superseded_at: null,
  considered: 1,
  relevant: 0,
  steps: {
    consequences: { items: [{ code: "У1.9", justification: "ПДн заявителей" }] },
    objects: {
      items: [{ key: "db", name: "СУБД", hosts: ["10.0.0.5"], impacts: ["ВВ1"], consequences: ["У1.9"] }],
    },
    intruders: {
      items: [
        { code: "НВ4", relevant: true, capability: "Н1", justification: "Интернет" },
        { code: "НВ11", relevant: true, capability: "Н1", justification: "Операторы" },
      ],
    },
    methods: { items: [{ code: "СР1", interfaces: "HTTPS", objects: ["db"], intruders: ["НВ4"] }] },
    scenarios: { items: [{ tactic: "Т2", techniques: [] }] },
  },
  threats: [THREAT],
  progress: {
    ...STEPS_DONE,
    done: 5,
    ready: false,
    steps: STEPS_DONE.steps.map((s) =>
      s.key === "threats" ? { ...s, done: false, count: 0, problems: ["УБИ.006: не принято решение об актуальности"] } : s,
    ),
  },
  unverified_refs: ["НВ4", "Т2", "У1.9"],
  bdu_version: "2026-10-01",
  snapshot: null,
  findings: { snapshot_id: "s2", snapshot_number: 2, imported: true, total: 2, unlinked: 2, confirmed_threats: 0 },
};

const KEY_LOG4J = "a".repeat(64);
const KEY_SSH = "b".repeat(64);

function finding(key: string, extra: Partial<FindingRow> = {}): FindingRow {
  return {
    dedup_key: key,
    module: "vuln",
    host: "10.0.0.5",
    port: 8080,
    finding_type: "vuln",
    title: "Apache Log4j: выполнение кода через подстановку JNDI",
    severity: "critical",
    vuln_id: "CVE-2021-44228",
    cve_ids: ["CVE-2021-44228"],
    bdu_ids: ["BDU:2021-06061"],
    cvss: 10,
    status: "open",
    detected_at: "2026-10-27T03:12:00Z",
    software: "Apache Log4j",
    software_version: "2.14.1",
    bdu: [
      {
        bdu_id: "BDU:2021-06061",
        title: "Уязвимость Log4j",
        in_bdu: true,
        withdrawn: false,
        cvss3_score: 10,
      },
    ],
    linked: [],
    objects: ["db"],
    suggested: [],
    ...extra,
  };
}

const FINDINGS: FindingsList = {
  ...MODEL.findings,
  items: [
    finding(KEY_LOG4J, { suggested: ["УБИ.006"] }),
    finding(KEY_SSH, {
      port: 22,
      title: "OpenSSH: состояние гонки в обработчике сигналов",
      severity: "high",
      bdu_ids: ["BDU:2024-04835"],
      bdu: [
        {
          bdu_id: "BDU:2024-04835",
          title: null,
          in_bdu: false,
          withdrawn: false,
          cvss3_score: null,
        },
      ],
      cvss: 8.1,
    }),
  ],
};


function renderAt(path: string) {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

function base(me: typeof METH, model: ModelDetail) {
  return {
    "GET /me": () => json(me),
    "GET /projects": () => json([PROJECT]),
    "GET /objects/o1": () => json(OBJ),
    "GET /objects/o1/hosts": () => json([{ id: "h1", address: "10.0.0.5", hostname: "db01" }]),
    "GET /refs/threats": () => json(REFS),
    "GET /objects/o1/threat-models": () => json([model]),
    "GET /threat-models/m1": () => json(model),
    "GET /threat-models/m1/findings": () => json(FINDINGS),
  };
}

it("пустая вкладка предлагает составить модель", async () => {
  const created = { ...MODEL, threats: [], considered: 0 };
  const calls = fakeApi({
    ...base(METH, MODEL),
    "GET /objects/o1/threat-models": () => json([]),
    "POST /objects/o1/threat-models": () => json(created, 201),
  });
  renderAt("/objects/o1?tab=threats");
  fireEvent.click(await screen.findByRole("button", { name: /Составить модель угроз/ }));
  await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/objects/o1/threat-models")).toBe(true));
});

it("шаг 1 сохраняет выбранные последствия с обоснованием", async () => {
  const calls = fakeApi({
    ...base(METH, MODEL),
    "PUT /threat-models/m1/steps/consequences": () => json(MODEL),
  });
  renderAt("/objects/o1?tab=threats");
  const wizard = await screen.findByRole("region", { name: "Мастер модели угроз" });
  const field = await within(wizard).findByLabelText("Обоснование У1.9");
  fireEvent.change(field, { target: { value: "Обрабатываются ПДн заявителей" } });
  fireEvent.click(within(wizard).getByRole("button", { name: /Сохранить шаг/ }));
  await waitFor(() =>
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({
      data: { items: [{ code: "У1.9", justification: "Обрабатываются ПДн заявителей" }] },
    }),
  );
});

it("угроза, признанная актуальной, получает предложенные связи по категории нарушителя", async () => {
  const calls = fakeApi({
    ...base(METH, MODEL),
    "PATCH /threat-models/m1/threats/УБИ.006": () => json(MODEL),
  });
  renderAt("/objects/o1?tab=threats");
  const wizard = await screen.findByRole("region", { name: "Мастер модели угроз" });
  fireEvent.click(within(wizard).getByRole("button", { name: /Угрозы БДУ/ }));
  expect(within(wizard).getByText("УБИ.006: не принято решение об актуальности")).toBeInTheDocument();
  fireEvent.click(within(wizard).getByRole("button", { name: "УБИ.006" }));

  const drawer = await screen.findByRole("dialog", { name: "УБИ.006" });
  fireEvent.click(within(drawer).getByRole("radio", { name: "Актуальна" }));
  // Внешний нарушитель из БДУ → предложен НВ4, внутренний НВ11 — нет.
  const intruders = within(drawer).getByRole("group", { name: "Нарушители" });
  expect(within(intruders).getByRole("button", { name: /НВ4/ })).toHaveAttribute("aria-pressed", "true");
  expect(within(intruders).getByRole("button", { name: /НВ11/ })).toHaveAttribute("aria-pressed", "false");
  fireEvent.change(within(drawer).getByLabelText("Обоснование"), { target: { value: "Портал в Интернете" } });
  fireEvent.click(within(drawer).getByRole("button", { name: /Сохранить/ }));
  await waitFor(() =>
    expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({
      relevant: true,
      justification: "Портал в Интернете",
      intruders: ["НВ4"],
      objects: ["db"],
      consequences: ["У1.9"],
      methods: ["СР1"],
      tactics: ["Т2"],
    }),
  );
});

it("утверждающий утверждает готовую модель только с подтверждением несверенного справочника", async () => {
  const ready: ModelDetail = {
    ...MODEL,
    relevant: 1,
    threats: [{ ...THREAT, relevant: true, justification: "Портал", intruders: ["НВ4"], objects: ["db"], consequences: ["У1.9"], methods: ["СР1"], tactics: ["Т2"] }],
    progress: STEPS_DONE,
  };
  const approved = { ...ready, status: "approved" as const, approved_by_name: "Смирнов С. С.", approved_at: "2026-11-04T12:00:00Z" };
  const calls = fakeApi({
    ...base(BOSS, ready),
    "POST /threat-models/m1/approve": () => json(approved),
  });
  renderAt("/objects/o1?tab=threats");
  const wizard = await screen.findByRole("region", { name: "Мастер модели угроз" });
  fireEvent.click(within(wizard).getByRole("button", { name: /Итог/ }));
  expect(within(wizard).getByText("Все шаги заполнены — модель можно утверждать.")).toBeInTheDocument();
  expect(within(wizard).getByText("Угроза внедрения кода или данных")).toBeInTheDocument();
  // Наблюдатель с правом утверждения не правит шаги.
  expect(within(wizard).queryByRole("button", { name: /Сохранить шаг/ })).not.toBeInTheDocument();
  fireEvent.click(within(wizard).getByRole("button", { name: /Утвердить модель/ }));

  const modal = await screen.findByRole("dialog", { name: "Утвердить модель угроз" });
  const submit = within(modal).getByRole("button", { name: "Утвердить" });
  expect(submit).toBeDisabled();
  fireEvent.click(within(modal).getByLabelText(/Утверждаю по несверенному справочнику/));
  fireEvent.click(submit);
  await waitFor(() =>
    expect(calls.find((c) => c.path === "/threat-models/m1/approve")?.body).toEqual({
      comment: null,
      acknowledge_unverified: true,
    }),
  );
});

it("составитель не может утвердить свою модель", async () => {
  const ready = { ...MODEL, progress: STEPS_DONE };
  fakeApi(base({ ...METH, permissions: [...METH.permissions, "approve"] }, ready));
  renderAt("/objects/o1?tab=threats");
  const wizard = await screen.findByRole("region", { name: "Мастер модели угроз" });
  fireEvent.click(within(wizard).getByRole("button", { name: /Итог/ }));
  expect(within(wizard).getByRole("button", { name: /Утвердить модель/ })).toBeDisabled();
  expect(within(wizard).getByText("Нельзя утвердить модель, которую вы составляли или правили")).toBeInTheDocument();
});

it("находки «Сканера» с БДУ привязываются к угрозе по подсказке и списком", async () => {
  const relevant: ModelThreat = {
    ...THREAT,
    relevant: true,
    justification: "Портал",
    objects: ["db"],
  };
  const linked: ModelDetail = {
    ...MODEL,
    edits: 8,
    threats: [
      {
        ...relevant,
        confirmed: 1,
        linked_findings: [
          {
            dedup_key: KEY_LOG4J,
            host: "10.0.0.5",
            port: 8080,
            title: "Apache Log4j: выполнение кода через подстановку JNDI",
            severity: "critical",
            vuln_id: "CVE-2021-44228",
            bdu_ids: ["BDU:2021-06061"],
            cve_ids: ["CVE-2021-44228"],
            cvss: 10,
            snapshot_number: 2,
            linked_at: "2026-11-04T12:00:00Z",
            linked_by_name: "Иванова А. А.",
            state: "present",
          },
        ],
      },
    ],
    findings: { ...MODEL.findings, unlinked: 1, confirmed_threats: 1 },
  };
  const calls = fakeApi({
    ...base(METH, { ...MODEL, threats: [relevant] }),
    "POST /threat-models/m1/threats/УБИ.006/findings": () => json(linked),
  });
  renderAt("/objects/o1?tab=threats");
  const wizard = await screen.findByRole("region", {
    name: "Мастер модели угроз",
  });
  fireEvent.click(within(wizard).getByRole("button", { name: /Угрозы БДУ/ }));
  expect(await within(wizard).findByText("Находки «Сканера» с БДУ")).toBeInTheDocument();
  expect(within(wizard).getByText(/BDU:2024-04835/)).toHaveTextContent("(нет в БДУ)");

  // Подсказка по объекту воздействия — привязка одной находки.
  fireEvent.click(within(wizard).getByTitle("Хост находки входит в объект воздействия угрозы"));
  await waitFor(() => expect(calls.filter((c) => c.method === "POST")).toHaveLength(1));
  expect(calls.find((c) => c.method === "POST")?.body).toEqual({
    dedup_keys: [KEY_LOG4J],
  });

  // Список: выбрать находку и угрозу.
  fireEvent.click(within(wizard).getByLabelText(/Выбрать 10.0.0.5:22/));
  fireEvent.change(within(wizard).getByLabelText("Угроза для привязки"), {
    target: { value: "УБИ.006" },
  });
  fireEvent.click(within(wizard).getByRole("button", { name: /Привязать выбранные \(1\)/ }));
  await waitFor(() => expect(calls.filter((c) => c.method === "POST")).toHaveLength(2));
  expect(calls.filter((c) => c.method === "POST")[1]?.body).toEqual({
    dedup_keys: [KEY_SSH],
  });
});

it("карточка угрозы показывает подтверждение находками и отвязывает", async () => {
  const threat: ModelThreat = {
    ...THREAT,
    relevant: false,
    justification: "Нет",
    confirmed: 1,
    linked_findings: [
      {
        dedup_key: KEY_LOG4J,
        host: "10.0.0.5",
        port: 8080,
        title: "Apache Log4j",
        severity: "critical",
        vuln_id: "CVE-2021-44228",
        bdu_ids: ["BDU:2021-06061"],
        cve_ids: [],
        cvss: 10,
        snapshot_number: 1,
        linked_at: "2026-11-04T12:00:00Z",
        linked_by_name: "Иванова А. А.",
        state: "present",
      },
      {
        dedup_key: KEY_SSH,
        host: "10.0.0.5",
        port: 22,
        title: "OpenSSH",
        severity: "high",
        vuln_id: "CVE-2024-6387",
        bdu_ids: ["BDU:2024-04835"],
        cve_ids: [],
        cvss: 8.1,
        snapshot_number: 1,
        linked_at: "2026-11-04T12:00:00Z",
        linked_by_name: "Иванова А. А.",
        state: "absent",
      },
    ],
  };
  const model: ModelDetail = {
    ...MODEL,
    threats: [threat],
    progress: {
      ...MODEL.progress,
      steps: MODEL.progress.steps.map((s) =>
        s.key === "threats"
          ? {
              ...s,
              warnings: ["УБИ.006: привязанных находок нет в снимке №2 (1) — устранены или хост не проверялся"],
            }
          : s,
      ),
    },
  };
  const calls = fakeApi({
    ...base(METH, model),
    [`DELETE /threat-models/m1/threats/УБИ.006/findings/${KEY_LOG4J}`]: () => json(MODEL),
  });
  renderAt("/objects/o1?tab=threats");
  const wizard = await screen.findByRole("region", {
    name: "Мастер модели угроз",
  });
  fireEvent.click(within(wizard).getByRole("button", { name: /Угрозы БДУ/ }));
  expect(within(wizard).getByRole("note")).toHaveTextContent("привязанных находок нет в снимке №2");
  fireEvent.click(within(wizard).getByRole("button", { name: "УБИ.006" }));
  const drawer = await screen.findByRole("dialog", { name: "УБИ.006" });
  expect(within(drawer).getByText("в снимке №2")).toBeInTheDocument();
  expect(within(drawer).getByText("нет в снимке №2")).toBeInTheDocument();
  expect(within(drawer).getByText(/признана неактуальной, но подтверждена/)).toBeInTheDocument();
  fireEvent.click(within(drawer).getByRole("button", { name: "Отвязать 10.0.0.5:8080" }));
  await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
});
