import { createBrowserRouter, Navigate } from 'react-router-dom'
import { AppShell } from './components/layout/AppShell'
import { LoginPage } from './pages/LoginPage'
import { DashboardPage } from './pages/DashboardPage'
import { BansPage } from './pages/BansPage'
import { CIDRsPage } from './pages/CIDRsPage'
import { FingerprintsPage } from './pages/FingerprintsPage'
import { DialPage } from './pages/DialPage'
import { PolicyPage } from './pages/PolicyPage'
import { ConfigPage } from './pages/ConfigPage'
import { AuditPage } from './pages/AuditPage'
import { HealthPage } from './pages/HealthPage'
import { AuthGuard } from './components/layout/AuthGuard'

export const router = createBrowserRouter([
  {
    path: '/login',
    element: <LoginPage />
  },
  {
    path: '/',
    element: <AuthGuard />,
    children: [
      {
        path: '',
        element: <AppShell />,
        children: [
          { index: true, element: <Navigate to="/dashboard" replace /> },
          { path: 'dashboard', element: <DashboardPage /> },
          { path: 'bans', element: <BansPage /> },
          { path: 'cidrs', element: <CIDRsPage /> },
          { path: 'fingerprints', element: <FingerprintsPage /> },
          { path: 'dial', element: <DialPage /> },
          { path: 'policy', element: <PolicyPage /> },
          { path: 'config', element: <ConfigPage /> },
          { path: 'audit', element: <AuditPage /> },
          { path: 'health', element: <HealthPage /> }
        ]
      }
    ]
  },
  {
    path: '*',
    element: <Navigate to="/" replace />
  }
])
