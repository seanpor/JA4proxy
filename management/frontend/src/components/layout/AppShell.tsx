import React, { useState } from 'react';
import { Link, useLocation, Outlet } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { Shield, Fingerprint, FileText, HeartPulse, ListChecks, Settings, Users, Phone, LayoutDashboard, Menu, X, LogOut } from 'lucide-react';

interface NavItem {
  name: string;
  path: string;
  icon: React.ReactNode;
}

const navItems: NavItem[] = [
  { name: 'Dashboard',    path: '/dashboard',    icon: <LayoutDashboard className="h-4 w-4" /> },
  { name: 'Bans',         path: '/bans',         icon: <Shield className="h-4 w-4" /> },
  { name: 'CIDRs',        path: '/cidrs',        icon: <Users className="h-4 w-4" /> },
  { name: 'Fingerprints', path: '/fingerprints', icon: <Fingerprint className="h-4 w-4" /> },
  { name: 'Dial',         path: '/dial',         icon: <Phone className="h-4 w-4" /> },
  { name: 'Policy',       path: '/policy',       icon: <ListChecks className="h-4 w-4" /> },
  { name: 'System',       path: '/config',       icon: <Settings className="h-4 w-4" /> },
  { name: 'Audit',        path: '/audit',        icon: <FileText className="h-4 w-4" /> },
  { name: 'Health',       path: '/health',       icon: <HeartPulse className="h-4 w-4" /> },
];

export const AppShell: React.FC<{ children?: React.ReactNode }> = ({ children }) => {
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();
  const { logout, username } = useAuth();

  const isActive = (path: string) => location.pathname === path || location.pathname.startsWith(path + '/');

  const SidebarContent = () => (
    <nav className="flex flex-col h-full">
      {/* Logo */}
      <div className="flex items-center gap-2 px-4 py-5 border-b border-gray-200">
        <Shield className="h-6 w-6 text-blue-600 flex-shrink-0" />
        <span className="font-bold text-gray-900 text-sm">JA4 Proxy</span>
      </div>

      {/* Nav links */}
      <div className="flex-1 overflow-y-auto py-4 px-2 space-y-1">
        {navItems.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            onClick={() => setMobileOpen(false)}
            className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
              isActive(item.path)
                ? 'bg-blue-50 text-blue-700'
                : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'
            }`}
          >
            {item.icon}
            {item.name}
          </Link>
        ))}
      </div>

      {/* User + logout */}
      <div className="border-t border-gray-200 p-4">
        <div className="flex items-center justify-between">
          <span className="text-xs text-gray-500 truncate">{username ?? 'admin'}</span>
          <button
            onClick={logout}
            className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-900 transition-colors"
          >
            <LogOut className="h-3 w-3" />
            Logout
          </button>
        </div>
      </div>
    </nav>
  );

  return (
    <div className="flex h-screen bg-gray-50 overflow-hidden">
      {/* Desktop sidebar */}
      <aside className="hidden md:flex md:flex-shrink-0 md:w-56 bg-white border-r border-gray-200 flex-col">
        <SidebarContent />
      </aside>

      {/* Mobile overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 flex md:hidden">
          <div
            className="fixed inset-0 bg-gray-600 bg-opacity-75"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="relative flex w-56 flex-col bg-white z-50">
            <button
              className="absolute top-3 right-3 text-gray-400 hover:text-gray-600"
              onClick={() => setMobileOpen(false)}
            >
              <X className="h-5 w-5" />
            </button>
            <SidebarContent />
          </aside>
        </div>
      )}

      {/* Main content */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        {/* Top bar (mobile only hamburger + page title) */}
        <header className="md:hidden flex items-center gap-3 px-4 py-3 bg-white border-b border-gray-200">
          <button
            onClick={() => setMobileOpen(true)}
            className="text-gray-500 hover:text-gray-700"
          >
            <Menu className="h-5 w-5" />
          </button>
          <span className="font-semibold text-gray-900 text-sm">JA4 Proxy</span>
        </header>

        <main className="flex-1 overflow-y-auto p-6">
          {children || <Outlet />}
        </main>
      </div>
    </div>
  );
};
