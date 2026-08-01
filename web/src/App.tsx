import { AdminShell } from './components/AdminShell'
import { AccountPage } from './pages/account/AccountPage'
import { AccountApplicationsPage } from './pages/account/AccountApplicationsPage'
import { AccountSecurityPage } from './pages/account/AccountSecurityPage'
import { AccountSessionsPage } from './pages/account/AccountSessionsPage'
import { ApplicationsPage } from './pages/admin/ApplicationsPage'
import { AuditPage } from './pages/admin/AuditPage'
import { CreateApplicationPage } from './pages/admin/CreateApplicationPage'
import { OverviewPage } from './pages/admin/OverviewPage'
import { SessionsPage } from './pages/admin/SessionsPage'
import { SettingsPage } from './pages/admin/SettingsPage'
import { UsersPage } from './pages/admin/UsersPage'
import { CompletePage } from './pages/auth/CompletePage'
import { ConsentPage } from './pages/auth/ConsentPage'
import { LoginPage } from './pages/auth/LoginPage'
import { RegisterPage } from './pages/auth/RegisterPage'
import { Redirect, RouterProvider } from './router'
import { useLocation } from './router-context'

function RouteView() {
  const { pathname } = useLocation()

  if (pathname === '/') return <Redirect to="/admin" />
  if (pathname === '/login') return <LoginPage />
  if (pathname === '/register') return <RegisterPage />
  if (pathname === '/consent') return <ConsentPage />
  if (pathname === '/complete') return <CompletePage />
  if (pathname === '/account') return <AccountPage />
  if (pathname === '/account/security') return <AccountSecurityPage />
  if (pathname === '/account/applications') return <AccountApplicationsPage />
  if (pathname === '/account/sessions') return <AccountSessionsPage />

  let adminPage
  switch (pathname) {
    case '/admin': adminPage = <OverviewPage />; break
    case '/admin/users': adminPage = <UsersPage />; break
    case '/admin/applications': adminPage = <ApplicationsPage />; break
    case '/admin/applications/new': adminPage = <CreateApplicationPage />; break
    case '/admin/sessions': adminPage = <SessionsPage />; break
    case '/admin/audit': adminPage = <AuditPage />; break
    case '/admin/settings':
    case '/admin/settings/registration':
    case '/admin/settings/authentication':
    case '/admin/settings/tokens':
    case '/admin/settings/keys': adminPage = <SettingsPage />; break
    default: return <Redirect to="/admin" />
  }

  return <AdminShell>{adminPage}</AdminShell>
}

function App() {
  return (
    <RouterProvider>
      <RouteView />
    </RouterProvider>
  )
}

export default App
