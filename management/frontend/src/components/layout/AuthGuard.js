"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthGuard = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_router_dom_1 = require("react-router-dom");
const useAuth_1 = require("../../hooks/useAuth");
const AuthGuard = ({ children }) => {
    const { isAuthenticated, isLoading } = (0, useAuth_1.useAuth)();
    if (isLoading) {
        return ((0, jsx_runtime_1.jsx)("div", { className: "min-h-screen flex items-center justify-center", children: (0, jsx_runtime_1.jsx)("div", { className: "text-muted-foreground", children: "Loading\u2026" }) }));
    }
    if (!isAuthenticated) {
        return (0, jsx_runtime_1.jsx)(react_router_dom_1.Navigate, { to: "/login", replace: true });
    }
    return children ? (0, jsx_runtime_1.jsx)(jsx_runtime_1.Fragment, { children: children }) : (0, jsx_runtime_1.jsx)(react_router_dom_1.Outlet, {});
};
exports.AuthGuard = AuthGuard;
