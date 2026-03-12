import { createBrowserRouter, Navigate } from 'react-router-dom'
import { AppShell } from './components/layout/AppShell.tsx'
import { LoginPage } from './pages/LoginPage.tsx'
import { DashboardPage } from './pages/DashboardPage.tsx'
import { BansPage } from './pages/BansPage.tsx'
import { CIDRsPage } from './pages/CIDRsPage.tsx'
import { FingerprintsPage } from './pages/FingerprintsPage.tsx'
import { DialPage } from './pages/DialPage.tsx'
import { PolicyPage } from './pages/PolicyPage.tsx'
import { ConfigPage } from './pages/ConfigPage.tsx'
import { AuditPage } from './pages/AuditPage.tsx'
import { HealthPage } from './pages/HealthPage.tsx'
import { AuthGuard } from './components/layout/AuthGuard.tsx'

// Create the router configuration
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
          { index: true, element: <DashboardPage /> },
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