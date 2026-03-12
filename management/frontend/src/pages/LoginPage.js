"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LoginPage = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const react_router_dom_1 = require("react-router-dom");
const useAuth_1 = require("../hooks/useAuth");
const Button_1 = require("../components/ui/Button");
const Input_1 = require("../components/ui/Input");
const Card_1 = require("../components/ui/Card");
const Alert_1 = require("../components/ui/Alert");
const LoginPage = () => {
    const [apiKey, setApiKey] = (0, react_1.useState)('');
    const [error, setError] = (0, react_1.useState)(null);
    const [isLoading, setIsLoading] = (0, react_1.useState)(false);
    const { login } = (0, useAuth_1.useAuth)();
    const navigate = (0, react_router_dom_1.useNavigate)();
    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setIsLoading(true);
        try {
            await login(apiKey);
            navigate('/dashboard', { replace: true });
        }
        catch (err) {
            console.error('Login failed:', err);
            setError('Invalid API key. Please try again.');
            setIsLoading(false);
        }
    };
    return ((0, jsx_runtime_1.jsx)("div", { className: "min-h-screen flex items-center justify-center bg-gray-50 p-4", children: (0, jsx_runtime_1.jsxs)(Card_1.Card, { className: "w-full max-w-md", children: [(0, jsx_runtime_1.jsxs)(Card_1.CardHeader, { children: [(0, jsx_runtime_1.jsx)(Card_1.CardTitle, { className: "text-2xl font-bold text-center", children: "JA4 Proxy Management" }), (0, jsx_runtime_1.jsx)(Card_1.CardDescription, { className: "text-center", children: "Enter your API key to access the management interface" })] }), (0, jsx_runtime_1.jsxs)(Card_1.CardContent, { children: [error && ((0, jsx_runtime_1.jsx)(Alert_1.Alert, { variant: "destructive", className: "mb-4", children: (0, jsx_runtime_1.jsx)(Alert_1.AlertDescription, { children: error }) })), (0, jsx_runtime_1.jsxs)("form", { onSubmit: handleSubmit, className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)("label", { htmlFor: "apiKey", className: "text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70", children: "API Key" }), (0, jsx_runtime_1.jsx)(Input_1.Input, { id: "apiKey", type: "password", value: apiKey, onChange: (e) => setApiKey(e.target.value), placeholder: "Enter your API key", required: true, className: "w-full" })] }), (0, jsx_runtime_1.jsx)(Button_1.Button, { type: "submit", className: "w-full", disabled: isLoading, children: isLoading ? 'Authenticating...' : 'Sign In' })] })] }), (0, jsx_runtime_1.jsx)(Card_1.CardFooter, { className: "text-center text-sm text-gray-500", children: (0, jsx_runtime_1.jsx)("p", { children: "JA4 Proxy Management UI v1.0" }) })] }) }));
};
exports.LoginPage = LoginPage;
