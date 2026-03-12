"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LoginPage = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const react_router_dom_1 = require("react-router-dom");
const useAuth_1 = require("../hooks/useAuth");
const ui_1 = require("../components/ui");
const LoginPage = () => {
    const [username, setUsername] = (0, react_1.useState)('');
    const [password, setPassword] = (0, react_1.useState)('');
    const [error, setError] = (0, react_1.useState)(null);
    const [isLoading, setIsLoading] = (0, react_1.useState)(false);
    const { login } = (0, useAuth_1.useAuth)();
    const navigate = (0, react_router_dom_1.useNavigate)();
    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setIsLoading(true);
        try {
            await login(username, password);
            navigate('/dashboard', { replace: true });
        }
        catch {
            setError('Invalid username or password. Please try again.');
            setIsLoading(false);
        }
    };
    return ((0, jsx_runtime_1.jsx)("div", { className: "min-h-screen flex items-center justify-center bg-gray-50 p-4", children: (0, jsx_runtime_1.jsxs)(ui_1.Card, { className: "w-full max-w-md", children: [(0, jsx_runtime_1.jsxs)(ui_1.CardHeader, { children: [(0, jsx_runtime_1.jsx)(ui_1.CardTitle, { className: "text-2xl font-bold text-center", children: "JA4 Proxy Management" }), (0, jsx_runtime_1.jsx)(ui_1.CardDescription, { className: "text-center", children: "Sign in to access the management interface" })] }), (0, jsx_runtime_1.jsxs)(ui_1.CardContent, { children: [error && ((0, jsx_runtime_1.jsx)(ui_1.Alert, { variant: "destructive", className: "mb-4", children: (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: error }) })), (0, jsx_runtime_1.jsxs)("form", { onSubmit: handleSubmit, className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)("label", { htmlFor: "username", className: "text-sm font-medium leading-none", children: "Username" }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "username", type: "text", value: username, onChange: (e) => setUsername(e.target.value), placeholder: "admin", autoComplete: "username", required: true, className: "w-full" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)("label", { htmlFor: "password", className: "text-sm font-medium leading-none", children: "Password" }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "password", type: "password", value: password, onChange: (e) => setPassword(e.target.value), placeholder: "Enter your password", autoComplete: "current-password", required: true, className: "w-full" })] }), (0, jsx_runtime_1.jsx)(ui_1.Button, { type: "submit", className: "w-full", disabled: isLoading, children: isLoading ? 'Signing in…' : 'Sign In' })] })] }), (0, jsx_runtime_1.jsx)(ui_1.CardFooter, { className: "text-center text-sm text-gray-500", children: (0, jsx_runtime_1.jsx)("p", { children: "JA4 Proxy Management UI" }) })] }) }));
};
exports.LoginPage = LoginPage;
