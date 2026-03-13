"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LoginPage = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const react_router_dom_1 = require("react-router-dom");
const useAuth_1 = require("../hooks/useAuth");
const lucide_react_1 = require("lucide-react");
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
            setError('Invalid username or password.');
            setIsLoading(false);
        }
    };
    return ((0, jsx_runtime_1.jsx)("div", { className: "min-h-screen flex items-center justify-center bg-gray-50", children: (0, jsx_runtime_1.jsxs)("div", { className: "w-full max-w-sm", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex flex-col items-center mb-8", children: [(0, jsx_runtime_1.jsx)("div", { className: "flex items-center justify-center w-14 h-14 rounded-2xl bg-blue-600 shadow-lg mb-4", children: (0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-7 w-7 text-white" }) }), (0, jsx_runtime_1.jsx)("h1", { className: "text-2xl font-bold text-gray-900", children: "JA4 Proxy" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-gray-500 mt-1", children: "Management Interface" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "bg-white rounded-xl border border-gray-200 shadow-sm p-8", children: [error && ((0, jsx_runtime_1.jsx)("div", { className: "mb-4 rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700", children: error })), (0, jsx_runtime_1.jsxs)("form", { onSubmit: handleSubmit, className: "space-y-5", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("label", { htmlFor: "username", className: "block text-sm font-medium text-gray-700 mb-1.5", children: "Username" }), (0, jsx_runtime_1.jsx)("input", { id: "username", type: "text", value: username, onChange: (e) => setUsername(e.target.value), placeholder: "admin", autoComplete: "username", required: true, className: "w-full h-9 rounded-md border border-gray-300 px-3 py-1 text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("label", { htmlFor: "password", className: "block text-sm font-medium text-gray-700 mb-1.5", children: "Password" }), (0, jsx_runtime_1.jsx)("input", { id: "password", type: "password", value: password, onChange: (e) => setPassword(e.target.value), placeholder: "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022", autoComplete: "current-password", required: true, className: "w-full h-9 rounded-md border border-gray-300 px-3 py-1 text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" })] }), (0, jsx_runtime_1.jsx)("button", { type: "submit", disabled: isLoading, className: "w-full h-9 rounded-md bg-blue-600 px-4 text-sm font-medium text-white shadow-sm hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors", children: isLoading ? 'Signing in…' : 'Sign in' })] })] })] }) }));
};
exports.LoginPage = LoginPage;
