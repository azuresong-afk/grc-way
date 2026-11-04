import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { App } from "../App";
import { TOKEN_KEY } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import { fakeApi, json } from "../test/fakeApi";

const METH = {
  id: "u2",
  username: "meth",
  display_name: "Иванова А. А.",
  roles: ["methodologist"],
  permissions: ["view", "objects.edit", "projects.manage"],
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

it("список объектов проекта и создание: режим подставляется по виду", async () => {
  sessionStorage.setItem(TOKEN_KEY, "tok");
  const calls = fakeApi({
    "GET /me": () => json(METH),
    "GET /projects": () => json([PROJECT]),
    "GET /projects/p1/objects": () =>
      json(
        [
          {
            id: "o1",
            project_id: "p1",
            kind: "gis",
            name: "ГИС «Учёт»",
            regime: "117",
            status: "active",
            internet: false,
            host_count: 10,
            segment_count: 3,
            updated_at: "2026-11-04T10:00:00Z",
          },
        ],
        200,
        { "X-Total-Count": "1" },
      ),
    "POST /projects/p1/objects": () => json({ id: "o2" }, 201),
    "GET /objects/o2": () => json({ detail: "нет" }, 404),
    "GET /objects/o2/hosts": () => json([]),
  });
  render(
    <MemoryRouter initialEntries={["/objects"]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );

  const row = (await screen.findByText("ГИС «Учёт»")).closest("tr")!;
  expect(within(row).getByText("ГИС")).toBeInTheDocument();
  expect(within(row).getByText("№117")).toBeInTheDocument();
  expect(within(row).getByText("10")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /Новый объект/ }));
  const dialog = await screen.findByRole("dialog");
  fireEvent.change(within(dialog).getByLabelText(/^Вид объекта/), { target: { value: "kii" } });
  expect(within(dialog).getByLabelText(/^Нормативный режим/)).toHaveValue("239");
  fireEvent.change(within(dialog).getByLabelText("Наименование"), { target: { value: "АСУ ТП" } });
  fireEvent.click(within(dialog).getByRole("button", { name: "Создать" }));

  await waitFor(() =>
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({
      kind: "kii",
      name: "АСУ ТП",
      regime: "239",
      purpose: null,
    }),
  );
});
