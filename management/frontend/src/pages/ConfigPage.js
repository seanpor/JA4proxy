"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConfigPage = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const Button_1 = require("../components/ui/Button");
const Card_1 = require("../components/ui/Card");
const Input_1 = require("../components/ui/Input");
const Label_1 = require("../components/ui/Label");
const Switch_1 = require("../components/ui/Switch");
const Alert_1 = require("../components/ui/Alert");
const lucide_react_1 = require("lucide-react");
const ConfigPage = () => {
    const [formData, setFormData] = (0, react_1.useState)({
        api_key: '',
        redis_url: 'redis://localhost:6379',
        debug_mode: false,
        auto_update: true,
        max_connections: 1000,
        rate_limit: 100,
    });
    const [isSubmitting, setIsSubmitting] = (0, react_1.useState)(false);
    const [submitError, setSubmitError] = (0, react_1.useState)(null);
    const [submitSuccess, setSubmitSuccess] = (0, react_1.useState)(false);
    const handleInputChange = (e) => {
        const { name, value, type } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: type === 'checkbox' ? e.target.checked : value,
        }));
    };
    const handleSwitchChange = (name, checked) => {
        setFormData(prev => ({
            ...prev,
            [name]: checked,
        }));
    };
    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        setSubmitError(null);
        setSubmitSuccess(false);
        try {
            // In a real implementation, this would call an API endpoint
            // await updateConfig(formData);
            console.log('Configuration saved:', formData);
            setSubmitSuccess(true);
            setTimeout(() => setSubmitSuccess(false), 3000);
        }
        catch (err) {
            console.error('Failed to update config:', err);
            setSubmitError('Failed to update configuration. Please try again.');
        }
        finally {
            setIsSubmitting(false);
        }
    };
    return ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-6", children: [(0, jsx_runtime_1.jsx)("div", { className: "flex justify-between items-center", children: (0, jsx_runtime_1.jsx)("h1", { className: "text-2xl font-bold", children: "System Configuration" }) }), submitError && ((0, jsx_runtime_1.jsxs)(Alert_1.Alert, { variant: "destructive", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(Alert_1.AlertDescription, { children: submitError })] })), submitSuccess && ((0, jsx_runtime_1.jsxs)(Alert_1.Alert, { variant: "success", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Settings, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(Alert_1.AlertDescription, { children: "Configuration updated successfully!" })] })), (0, jsx_runtime_1.jsxs)(Card_1.Card, { children: [(0, jsx_runtime_1.jsxs)(Card_1.CardHeader, { children: [(0, jsx_runtime_1.jsx)(Card_1.CardTitle, { children: "General Settings" }), (0, jsx_runtime_1.jsx)(Card_1.CardDescription, { children: "Configure the basic system parameters" })] }), (0, jsx_runtime_1.jsx)(Card_1.CardContent, { children: (0, jsx_runtime_1.jsx)("form", { onSubmit: handleSubmit, className: "space-y-6", children: (0, jsx_runtime_1.jsxs)("div", { className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(Label_1.Label, { htmlFor: "redis_url", children: "Redis Connection URL" }), (0, jsx_runtime_1.jsx)(Input_1.Input, { id: "redis_url", name: "redis_url", value: formData.redis_url, onChange: handleInputChange, placeholder: "redis://localhost:6379" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-muted-foreground", children: "URL for Redis database connection" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(Label_1.Label, { htmlFor: "max_connections", children: "Max Connections" }), (0, jsx_runtime_1.jsx)(Input_1.Input, { id: "max_connections", name: "max_connections", type: "number", min: "10", max: "10000", value: formData.max_connections, onChange: handleInputChange }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-muted-foreground", children: "Maximum concurrent connections allowed" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(Label_1.Label, { htmlFor: "rate_limit", children: "Rate Limit (req/min)" }), (0, jsx_runtime_1.jsx)(Input_1.Input, { id: "rate_limit", name: "rate_limit", type: "number", min: "10", max: "10000", value: formData.rate_limit, onChange: handleInputChange }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-muted-foreground", children: "API rate limit in requests per minute" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2 pt-4", children: [(0, jsx_runtime_1.jsx)(Switch_1.Switch, { id: "debug_mode", name: "debug_mode", checked: formData.debug_mode, onCheckedChange: (checked) => handleSwitchChange('debug_mode', checked) }), (0, jsx_runtime_1.jsx)(Label_1.Label, { htmlFor: "debug_mode", children: "Debug Mode" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-muted-foreground ml-auto", children: "Enable verbose logging and debugging" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center space-x-2", children: [(0, jsx_runtime_1.jsx)(Switch_1.Switch, { id: "auto_update", name: "auto_update", checked: formData.auto_update, onCheckedChange: (checked) => handleSwitchChange('auto_update', checked) }), (0, jsx_runtime_1.jsx)(Label_1.Label, { htmlFor: "auto_update", children: "Auto Update" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-muted-foreground ml-auto", children: "Automatically check for and apply updates" })] }), (0, jsx_runtime_1.jsx)("div", { className: "pt-4 border-t", children: (0, jsx_runtime_1.jsxs)(Button_1.Button, { type: "submit", disabled: isSubmitting, children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Save, { className: "h-4 w-4 mr-2" }), isSubmitting ? 'Saving...' : 'Save Configuration'] }) })] }) }) })] }), (0, jsx_runtime_1.jsxs)(Card_1.Card, { children: [(0, jsx_runtime_1.jsxs)(Card_1.CardHeader, { children: [(0, jsx_runtime_1.jsx)(Card_1.CardTitle, { children: "Security Settings" }), (0, jsx_runtime_1.jsx)(Card_1.CardDescription, { children: "Configure security-related parameters" })] }), (0, jsx_runtime_1.jsxs)(Card_1.CardContent, { className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(Label_1.Label, { htmlFor: "api_key", children: "API Key" }), (0, jsx_runtime_1.jsxs)("div", { className: "flex gap-2", children: [(0, jsx_runtime_1.jsx)(Input_1.Input, { id: "api_key", name: "api_key", type: "password", value: formData.api_key, onChange: handleInputChange, placeholder: "Generate or paste API key" }), (0, jsx_runtime_1.jsx)(Button_1.Button, { variant: "secondary", type: "button", children: "Generate" })] }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-muted-foreground", children: "API key for management interface access" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-4 pt-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between py-2 border-b", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "IP Ban Duration" })] }), (0, jsx_runtime_1.jsx)("span", { className: "font-mono", children: "24 hours" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between py-2 border-b", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Network, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "Allowed CIDR Ranges" })] }), (0, jsx_runtime_1.jsx)("span", { className: "font-mono", children: "5 configured" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between py-2 border-b", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Fingerprint, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "Blocked Fingerprints" })] }), (0, jsx_runtime_1.jsx)("span", { className: "font-mono", children: "12 configured" })] })] })] })] }), (0, jsx_runtime_1.jsxs)(Card_1.Card, { children: [(0, jsx_runtime_1.jsxs)(Card_1.CardHeader, { children: [(0, jsx_runtime_1.jsx)(Card_1.CardTitle, { children: "Advanced Settings" }), (0, jsx_runtime_1.jsx)(Card_1.CardDescription, { children: "Advanced configuration options" })] }), (0, jsx_runtime_1.jsx)(Card_1.CardContent, { children: (0, jsx_runtime_1.jsxs)("div", { className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)(Alert_1.Alert, { variant: "warning", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(Alert_1.AlertDescription, { children: "These settings should only be modified if you understand their impact on system performance and security." })] }), (0, jsx_runtime_1.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(Label_1.Label, { htmlFor: "worker_threads", children: "Worker Threads" }), (0, jsx_runtime_1.jsx)(Input_1.Input, { id: "worker_threads", name: "worker_threads", type: "number", min: "1", max: "32", defaultValue: "4" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-muted-foreground", children: "Number of worker threads for processing" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(Label_1.Label, { htmlFor: "cache_ttl", children: "Cache TTL (seconds)" }), (0, jsx_runtime_1.jsx)(Input_1.Input, { id: "cache_ttl", name: "cache_ttl", type: "number", min: "60", max: "86400", defaultValue: "300" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-muted-foreground", children: "Time-to-live for cached data" })] })] })] }) })] })] }));
};
exports.ConfigPage = ConfigPage;
