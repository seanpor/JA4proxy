import React, { useState } from 'react';
import { Link, useLocation, Outlet } from 'react-router-dom';
import { Button, Sheet, SheetContent, SheetTrigger } from '../ui';
import { Menu, Package2, PanelLeft, Search, Users, Settings, Shield, Fingerprint, Phone, FileText, HeartPulse, ListChecks } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';

interface NavItem {
  name: string;
  path: string;
  icon: React.ReactNode;
}

export const AppShell: React.FC<{ children?: React.ReactNode }> = ({ children }) => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const location = useLocation();
  const { logout } = useAuth();

  const navItems: NavItem[] = [
    { name: 'Dashboard', path: '/dashboard', icon: <Package2 className="h-4 w-4" /> },
    { name: 'Bans', path: '/bans', icon: <Shield className="h-4 w-4" /> },
    { name: 'CIDRs', path: '/cidrs', icon: <Users className="h-4 w-4" /> },
    { name: 'Fingerprints', path: '/fingerprints', icon: <Fingerprint className="h-4 w-4" /> },
    { name: 'Dial', path: '/dial', icon: <Phone className="h-4 w-4" /> },
    { name: 'Policy', path: '/policy', icon: <ListChecks className="h-4 w-4" /> },
    { name: 'Config', path: '/config', icon: <Settings className="h-4 w-4" /> },
    { name: 'Audit', path: '/audit', icon: <FileText className="h-4 w-4" /> },
    { name: 'Health', path: '/health', icon: <HeartPulse className="h-4 w-4" /> },
  ];

  const handleLogout = async () => {
    await logout();
  };

  return (
    <div className="flex min-h-screen w-full flex-col bg-muted/40">
      <div className="flex flex-col sm:gap-4 sm:py-4">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-4 border-b bg-background px-4 sm:static sm:h-auto sm:border-0 sm:bg-transparent sm:px-6">
          <Sheet>
            <SheetTrigger>
              <Button size="icon" variant="outline" className="sm:hidden">
                <PanelLeft className="h-5 w-5" />
                <span className="sr-only">Toggle Menu</span>
              </Button>
            </SheetTrigger>
            <SheetContent className="sm:max-w-xs">
              <nav className="grid gap-6 text-lg font-medium">
                <Link to="/dashboard" className="group flex h-10 w-10 shrink-0 items-center justify-center gap-2 rounded-full bg-primary text-lg font-semibold text-primary-foreground md:text-base">
                  <Package2 className="h-5 w-5 transition-all group-hover:scale-110" />
                  <span className="sr-only">JA4 Proxy</span>
                </Link>
                {navItems.map((item) => (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`flex items-center gap-4 px-2.5 ${location.pathname === item.path ? 'text-foreground' : 'text-muted-foreground hover:text-foreground'}`}
                  >
                    {item.icon}
                    {item.name}
                  </Link>
                ))}
              </nav>
            </SheetContent>
          </Sheet>

          <div className="relative ml-auto flex-1 md:grow-0">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <input
              type="search"
              placeholder="Search..."
              className="w-full rounded-lg bg-background pl-8 md:w-[200px] lg:w-[336px]"
            />
          </div>

          <Button variant="outline" size="icon" className="ml-2" onClick={handleLogout}>
            <Menu className="h-5 w-5" />
            <span className="sr-only">Logout</span>
          </Button>
        </header>

        <main className="grid flex-1 items-start gap-4 p-4 sm:px-6 sm:py-0 md:gap-8">
          <div className="mx-auto grid w-full max-w-6xl flex-1 auto-rows-max gap-4">
            {children || <Outlet />}
          </div>
        </main>
      </div>
    </div>
  );
};