import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { RequireAuth, RequirePerm } from "./lib/auth";
import { PLATFORM, goToLogin } from "./lib/platform";
import { PlatformEventsPage } from "./pages/PlatformEventsPage";
import { ProjectProvider } from "./lib/project";
import { AuditPage } from "./pages/AuditPage";
import { BduPage } from "./pages/BduPage";
import { ClassTablesPage } from "./pages/ClassTablesPage";
import { LoginPage } from "./pages/LoginPage";
import { ObjectPage } from "./pages/ObjectPage";
import { ObjectsPage } from "./pages/ObjectsPage";
import { ProjectPage } from "./pages/ProjectPage";
import { ProjectsPage } from "./pages/ProjectsPage";
import { RefsPage } from "./pages/RefsPage";
import { ScannerSyncPage } from "./pages/ScannerSyncPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { SummaryPage } from "./pages/SummaryPage";
import { SziRegistryPage } from "./pages/SziRegistryPage";
import { VulnCriticalityPage } from "./pages/VulnCriticalityPage";
import { DocumentsPage } from "./pages/DocumentsPage";
import { ThreatRefsPage } from "./pages/ThreatRefsPage";
import { UsersPage } from "./pages/UsersPage";

/** В платформе своей страницы входа нет — уводим на вход оболочки с тем же next. */
function ShellLogin() {
  const next = new URLSearchParams(window.location.search).get("next");
  goToLogin(next ?? import.meta.env.BASE_URL);
  return null;
}

export function App() {
  return (
    <Routes>
      <Route path="login" element={PLATFORM ? <ShellLogin /> : <LoginPage />} />
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
          path="objects"
          element={
            <RequirePerm perm="view">
              <ObjectsPage />
            </RequirePerm>
          }
        />
        <Route
          path="objects/:id"
          element={
            <RequirePerm perm="view">
              <ObjectPage />
            </RequirePerm>
          }
        />
        <Route path="refs" element={<RefsPage />} />
        <Route path="refs/scanner" element={<ScannerSyncPage />} />
        <Route path="refs/classification" element={<ClassTablesPage />} />
        <Route path="refs/threats" element={<ThreatRefsPage />} />
        <Route path="refs/bdu" element={<BduPage />} />
        <Route path="refs/szi" element={<SziRegistryPage />} />
        <Route path="refs/vuln-criticality" element={<VulnCriticalityPage />} />
        <Route path="refs/documents" element={<DocumentsPage />} />
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
        <Route
          path="admin/platform"
          element={
            <RequirePerm perm="integrations.manage">
              <PlatformEventsPage />
            </RequirePerm>
          }
        />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
