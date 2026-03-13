"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppShell = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const react_router_dom_1 = require("react-router-dom");
const useAuth_1 = require("../../hooks/useAuth");
const lucide_react_1 = require("lucide-react");
const navItems = [
    { name: 'Dashboard', path: '/dashboard', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.LayoutDashboard, { className: "h-4 w-4" }) },
    { name: 'Bans', path: '/bans', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-4 w-4" }) },
    { name: 'CIDRs', path: '/cidrs', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Users, { className: "h-4 w-4" }) },
    { name: 'Fingerprints', path: '/fingerprints', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Fingerprint, { className: "h-4 w-4" }) },
    { name: 'Dial', path: '/dial', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Phone, { className: "h-4 w-4" }) },
    { name: 'Policy', path: '/policy', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.ListChecks, { className: "h-4 w-4" }) },
    { name: 'Config', path: '/config', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Settings, { className: "h-4 w-4" }) },
    { name: 'Audit', path: '/audit', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.FileText, { className: "h-4 w-4" }) },
    { name: 'Health', path: '/health', icon: (0, jsx_runtime_1.jsx)(lucide_react_1.HeartPulse, { className: "h-4 w-4" }) },
];
const AppShell = ({ children }) => {
    const [mobileOpen, setMobileOpen] = (0, react_1.useState)(false);
    const location = (0, react_router_dom_1.useLocation)();
    const { logout, username } = (0, useAuth_1.useAuth)();
    const isActive = (path) => location.pathname === path || location.pathname.startsWith(path + '/');
    const SidebarContent = () => ((0, jsx_runtime_1.jsxs)("nav", { className: "flex flex-col h-full", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2 px-4 py-5 border-b border-gray-200", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-6 w-6 text-blue-600 flex-shrink-0" }), (0, jsx_runtime_1.jsx)("span", { className: "font-bold text-gray-900 text-sm", children: "JA4 Proxy" })] }), (0, jsx_runtime_1.jsx)("div", { className: "flex-1 overflow-y-auto py-4 px-2 space-y-1", children: navItems.map((item) => ((0, jsx_runtime_1.jsxs)(react_router_dom_1.Link, { to: item.path, onClick: () => setMobileOpen(false), className: `flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors ${isActive(item.path)
                        ? 'bg-blue-50 text-blue-700'
                        : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900'}`, children: [item.icon, item.name] }, item.path))) }), (0, jsx_runtime_1.jsx)("div", { className: "border-t border-gray-200 p-4", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsx)("span", { className: "text-xs text-gray-500 truncate", children: username ?? 'admin' }), (0, jsx_runtime_1.jsxs)("button", { onClick: logout, className: "flex items-center gap-1 text-xs text-gray-500 hover:text-gray-900 transition-colors", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.LogOut, { className: "h-3 w-3" }), "Logout"] })] }) })] }));
    return ((0, jsx_runtime_1.jsxs)("div", { className: "flex h-screen bg-gray-50 overflow-hidden", children: [(0, jsx_runtime_1.jsx)("aside", { className: "hidden md:flex md:flex-shrink-0 md:w-56 bg-white border-r border-gray-200 flex-col", children: (0, jsx_runtime_1.jsx)(SidebarContent, {}) }), mobileOpen && ((0, jsx_runtime_1.jsxs)("div", { className: "fixed inset-0 z-40 flex md:hidden", children: [(0, jsx_runtime_1.jsx)("div", { className: "fixed inset-0 bg-gray-600 bg-opacity-75", onClick: () => setMobileOpen(false) }), (0, jsx_runtime_1.jsxs)("aside", { className: "relative flex w-56 flex-col bg-white z-50", children: [(0, jsx_runtime_1.jsx)("button", { className: "absolute top-3 right-3 text-gray-400 hover:text-gray-600", onClick: () => setMobileOpen(false), children: (0, jsx_runtime_1.jsx)(lucide_react_1.X, { className: "h-5 w-5" }) }), (0, jsx_runtime_1.jsx)(SidebarContent, {})] })] })), (0, jsx_runtime_1.jsxs)("div", { className: "flex flex-col flex-1 min-w-0 overflow-hidden", children: [(0, jsx_runtime_1.jsxs)("header", { className: "md:hidden flex items-center gap-3 px-4 py-3 bg-white border-b border-gray-200", children: [(0, jsx_runtime_1.jsx)("button", { onClick: () => setMobileOpen(true), className: "text-gray-500 hover:text-gray-700", children: (0, jsx_runtime_1.jsx)(lucide_react_1.Menu, { className: "h-5 w-5" }) }), (0, jsx_runtime_1.jsx)("span", { className: "font-semibold text-gray-900 text-sm", children: "JA4 Proxy" })] }), (0, jsx_runtime_1.jsx)("main", { className: "flex-1 overflow-y-auto p-6", children: children || (0, jsx_runtime_1.jsx)(react_router_dom_1.Outlet, {}) })] })] }));
};
exports.AppShell = AppShell;
