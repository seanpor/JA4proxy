"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.router = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_router_dom_1 = require("react-router-dom");
const AppShell_1 = require("./components/layout/AppShell");
const LoginPage_1 = require("./pages/LoginPage");
const DashboardPage_1 = require("./pages/DashboardPage");
const BansPage_1 = require("./pages/BansPage");
const CIDRsPage_1 = require("./pages/CIDRsPage");
const FingerprintsPage_1 = require("./pages/FingerprintsPage");
const DialPage_1 = require("./pages/DialPage");
const PolicyPage_1 = require("./pages/PolicyPage");
const ConfigPage_1 = require("./pages/ConfigPage");
const AuditPage_1 = require("./pages/AuditPage");
const HealthPage_1 = require("./pages/HealthPage");
const AuthGuard_1 = require("./components/layout/AuthGuard");
// Create the router configuration
exports.router = (0, react_router_dom_1.createBrowserRouter)([
    {
        path: '/login',
        element: (0, jsx_runtime_1.jsx)(LoginPage_1.LoginPage, {})
    },
    {
        path: '/',
        element: (0, jsx_runtime_1.jsx)(AuthGuard_1.AuthGuard, {}),
        children: [
            {
                path: '',
                element: (0, jsx_runtime_1.jsx)(AppShell_1.AppShell, {}),
                children: [
                    { index: true, element: (0, jsx_runtime_1.jsx)(DashboardPage_1.DashboardPage, {}) },
                    { path: 'bans', element: (0, jsx_runtime_1.jsx)(BansPage_1.BansPage, {}) },
                    { path: 'cidrs', element: (0, jsx_runtime_1.jsx)(CIDRsPage_1.CIDRsPage, {}) },
                    { path: 'fingerprints', element: (0, jsx_runtime_1.jsx)(FingerprintsPage_1.FingerprintsPage, {}) },
                    { path: 'dial', element: (0, jsx_runtime_1.jsx)(DialPage_1.DialPage, {}) },
                    { path: 'policy', element: (0, jsx_runtime_1.jsx)(PolicyPage_1.PolicyPage, {}) },
                    { path: 'config', element: (0, jsx_runtime_1.jsx)(ConfigPage_1.ConfigPage, {}) },
                    { path: 'audit', element: (0, jsx_runtime_1.jsx)(AuditPage_1.AuditPage, {}) },
                    { path: 'health', element: (0, jsx_runtime_1.jsx)(HealthPage_1.HealthPage, {}) }
                ]
            }
        ]
    },
    {
        path: '*',
        element: (0, jsx_runtime_1.jsx)(react_router_dom_1.Navigate, { to: "/", replace: true })
    }
]);
