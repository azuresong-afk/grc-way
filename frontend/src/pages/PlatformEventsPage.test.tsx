import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import { fakeApi, json } from "../test/fakeApi";

const ADMIN = {
  id: "u1",
  username: "root",
  display_name: "Администратор",
  roles: ["admin"],
  permissions: ["users.manage", "refs.manage", "integrations.manage", "audit.view"],
};

const STATUS = {
  auth_mode: "platform",
  product_id: "grc",
  platform_url: "http://platform-api:8000",
  jwks_url: "http://platform-api:8000/.well-known/jwks.json",
  events_url: "http://platform-api:8000/events",
  events_secret_set: true,
  outbox_enabled: true,
  counts: { pending: 1, delivered: 40, rejected: 0, dead: 1 },
  shadow_users: 4,
  shadow_projects: 2,
  last_inbox_at: "2026-11-05T12:00:00Z",
};

const DEAD = {
  id: "e1",
  type: "grc.assessment.updated",
  project_id: "p1",
  subject: "system/o1",
  status: "dead",
  attempts: 5,
  next_at: "2026-11-05T12:00:00Z",
  last_error: "HTTP 503: ",
  created_at: "2026-11-05T10:00:00Z",
  delivered_at: null,
  data: { title: "ГИС «Учёт»", percent: 64 },
};

it("События платформы: состояние, недоставленное и повторная отправка", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  let retried = false;
  const calls = fakeApi({
    "GET /me": () => json(ADMIN),
    "GET /outbox/status": () => json(STATUS),
    "GET /outbox": () =>
      json([retried ? { ...DEAD, status: "pending", attempts: 0 } : DEAD], 200, { "X-Total-Count": "1" }),
    "POST /outbox/e1/retry": () => {
      retried = true;
      return json({ ...DEAD, status: "pending" });
    },
  });
  render(
    <MemoryRouter initialEntries={["/admin/platform"]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );

  expect(await screen.findByText("4 теневых пользователей · 2 проектов")).toBeInTheDocument();
  const row = (await screen.findByText("ГИС «Учёт» · 64 %")).closest("tr")!;
  expect(within(row).getByText("Не доставлено")).toBeInTheDocument();
  fireEvent.click(within(row).getByRole("button", { name: "Отправить повторно" }));
  await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
  expect(await within(row).findByText("В очереди")).toBeInTheDocument();
});
