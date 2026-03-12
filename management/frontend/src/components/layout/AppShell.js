"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppShell = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const react_router_dom_1 = require("react-router-dom");
const ui_1 = require("../ui");
const lucide_react_1 = require("lucide-react");
const useAuth_1 = require("../../hooks/useAuth");
const AppShell = ({ children }) => {
    const [isCollapsed, setIsCollapsed] = (0, react_1.useState)(false);
    const location = (0, react_router_dom_1.useLocation)();
    const { logout } = (0, useAuth_1.useAuth)();
    const navItems = [
        { name: 'Dashboard', path: '/dashboard', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Package2, { className: "h-4 w-4" }) },
        { name: 'Bans', path: '/bans', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-4 w-4" }) },
        { name: 'CIDRs', path: '/cidrs', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Users, { className: "h-4 w-4" }) },
        { name: 'Fingerprints', path: '/fingerprints', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Fingerprint, { className: "h-4 w-4" }) },
        { name: 'Dial', path: '/dial', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Phone, { className: "h-4 w-4" }) },
        { name: 'Policy', path: '/policy', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.ListChecks, { className: "h-4 w-4" }) },
        { name: 'Config', path: '/config', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Settings, { className: "h-4 w-4" }) },
        { name: 'Audit', path: '/audit', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.FileText, { className: "h-4 w-4" }) },
        { name: 'Health', path: '/health', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.HeartPulse, { className: "h-4 w-4" }) },
    ];
    const handleLogout = async () => {
        await logout();
    };
    return ((0, jsx_runtime_1.jsx)("div", { className: "flex min-h-screen w-full flex-col bg-muted/40", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex flex-col sm:gap-4 sm:py-4", children: [(0, jsx_runtime_1.jsxs)("header", { className: "sticky top-0 z-30 flex h-14 items-center gap-4 border-b bg-background px-4 sm:static sm:h-auto sm:border-0 sm:bg-transparent sm:px-6", children: [(0, jsx_runtime_1.jsxs)(ui_1.Sheet, { children: [(0, jsx_runtime_1.jsx)(ui_1.SheetTrigger, { children: (0, jsx_runtime_1.jsxs)(ui_1.Button, { size: "icon", variant: "outline", className: "sm:hidden", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.PanelLeft, { className: "h-5 w-5" }), (0, jsx_runtime_1.jsx)("span", { className: "sr-only", children: "Toggle Menu" })] }) }), (0, jsx_runtime_1.jsx)(ui_1.SheetContent, { className: "sm:max-w-xs", children: (0, jsx_runtime_1.jsxs)("nav", { className: "grid gap-6 text-lg font-medium", children: [(0, jsx_runtime_1.jsxs)(react_router_dom_1.Link, { to: "/dashboard", className: "group flex h-10 w-10 shrink-0 items-center justify-center gap-2 rounded-full bg-primary text-lg font-semibold text-primary-foreground md:text-base", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Package2, { className: "h-5 w-5 transition-all group-hover:scale-110" }), (0, jsx_runtime_1.jsx)("span", { className: "sr-only", children: "JA4 Proxy" })] }), navItems.map((item) => ((0, jsx_runtime_1.jsxs)(react_router_dom_1.Link, { to: item.path, className: `flex items-center gap-4 px-2.5 ${location.pathname === item.path ? 'text-foreground' : 'text-muted-foreground hover:text-foreground'}`, children: [item.icon, item.name] }, item.path)))] }) })] }), (0, jsx_runtime_1.jsxs)("div", { className: "relative ml-auto flex-1 md:grow-0", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Search, { className: "absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" }), (0, jsx_runtime_1.jsx)("input", { type: "search", placeholder: "Search...", className: "w-full rounded-lg bg-background pl-8 md:w-[200px] lg:w-[336px]" })] }), (0, jsx_runtime_1.jsxs)(ui_1.Button, { variant: "outline", size: "icon", className: "ml-2", onClick: handleLogout, children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Menu, { className: "h-5 w-5" }), (0, jsx_runtime_1.jsx)("span", { className: "sr-only", children: "Logout" })] })] }), (0, jsx_runtime_1.jsx)("main", { className: "grid flex-1 items-start gap-4 p-4 sm:px-6 sm:py-0 md:gap-8", children: (0, jsx_runtime_1.jsx)("div", { className: "mx-auto grid w-full max-w-6xl flex-1 auto-rows-max gap-4", children: children || (0, jsx_runtime_1.jsx)(react_router_dom_1.Outlet, {}) }) })] }) }));
};
exports.AppShell = AppShell;
