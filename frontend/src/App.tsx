import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { RequireAuth, RequirePerm } from "./lib/auth";
import { ProjectProvider } from "./lib/project";
import { AuditPage } from "./pages/AuditPage";
import { LoginPage } from "./pages/LoginPage";
import { ProjectPage } from "./pages/ProjectPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { SummaryPage } from "./pages/SummaryPage";
import { UsersPage } from "./pages/UsersPage";

export function App() {
  return (
    <Routes>
      <Route path="login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <ProjectProvider>
              <Layout />
            </ProjectProvider>
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/summary" replace />} />
        <Route path="summary" element={<SummaryPage />} />
        <Route
          path="projects"
          element={
            <RequirePerm perm="view">
              <ProjectsPage />
            </RequirePerm>
          }
        />
        <Route
          path="projects/:id"
          element={
            <RequirePerm perm="view">
              <ProjectPage />
            </RequirePerm>
          }
        />
        <Route
          path="admin/users"
          element={
            <RequirePerm perm="users.manage">
              <UsersPage />
            </RequirePerm>
          }
        />
        <Route
          path="admin/audit"
          element={
            <RequirePerm perm="audit.view">
              <AuditPage />
            </RequirePerm>
          }
        />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
