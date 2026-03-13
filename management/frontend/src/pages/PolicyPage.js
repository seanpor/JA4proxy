"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyPage = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = __importStar(require("react"));
const useApi_1 = require("../hooks/useApi");
const ui_1 = require("../components/ui");
const lucide_react_1 = require("lucide-react");
const PolicyPage = () => {
    const { data: config, isLoading, error, updateThresholdConfig } = (0, useApi_1.useThresholdConfig)();
    const [formData, setFormData] = (0, react_1.useState)({
        flag: config?.flag ?? 20,
        rate_limit: config?.rate_limit ?? 35,
        tarpit: config?.tarpit ?? 55,
        block: config?.block ?? 70,
        ban: config?.ban ?? 85,
    });
    const [isSubmitting, setIsSubmitting] = (0, react_1.useState)(false);
    const [submitError, setSubmitError] = (0, react_1.useState)(null);
    const [submitSuccess, setSubmitSuccess] = (0, react_1.useState)(false);
    // Update form data when config loads
    react_1.default.useEffect(() => {
        if (config) {
            setFormData({
                flag: config.flag,
                rate_limit: config.rate_limit,
                tarpit: config.tarpit,
                block: config.block,
                ban: config.ban,
            });
        }
    }, [config]);
    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: parseInt(value) || 0,
        }));
    };
    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        setSubmitError(null);
        setSubmitSuccess(false);
        try {
            await updateThresholdConfig(formData);
            setSubmitSuccess(true);
            setTimeout(() => setSubmitSuccess(false), 3000);
        }
        catch (err) {
            console.error('Failed to update config:', err);
            setSubmitError('Failed to update configuration. Thresholds must be in ascending order: flag ≤ rate_limit ≤ tarpit ≤ block ≤ ban.');
        }
        finally {
            setIsSubmitting(false);
        }
    };
    const thresholdFields = [
        { key: 'flag', label: 'Flag (score ≥)', description: 'Score to flag a connection for review' },
        { key: 'rate_limit', label: 'Rate Limit (score ≥)', description: 'Score to apply rate limiting' },
        { key: 'tarpit', label: 'Tarpit (score ≥)', description: 'Score to tarpit the connection' },
        { key: 'block', label: 'Block (score ≥)', description: 'Score to block the connection' },
        { key: 'ban', label: 'Ban (score ≥)', description: 'Score to ban the IP address' },
    ];
    return ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-6", children: [(0, jsx_runtime_1.jsx)("div", { className: "flex justify-between items-center", children: (0, jsx_runtime_1.jsx)("h1", { className: "text-2xl font-bold", children: "Policy Configuration" }) }), error && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsxs)(ui_1.AlertDescription, { children: ["Failed to load configuration: ", error.message] })] })), submitError && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: submitError })] })), submitSuccess && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: "Configuration updated successfully!" })] })), (0, jsx_runtime_1.jsxs)(ui_1.Card, { children: [(0, jsx_runtime_1.jsxs)(ui_1.CardHeader, { children: [(0, jsx_runtime_1.jsx)(ui_1.CardTitle, { children: "Risk Score Thresholds" }), (0, jsx_runtime_1.jsx)(ui_1.CardDescription, { children: "Connections are scored 0\u2013100. Each threshold triggers an action when the score meets or exceeds it. Thresholds must be in ascending order." })] }), (0, jsx_runtime_1.jsx)(ui_1.CardContent, { children: isLoading ? ((0, jsx_runtime_1.jsx)("div", { className: "text-center py-8", children: "Loading configuration..." })) : ((0, jsx_runtime_1.jsxs)("form", { onSubmit: handleSubmit, className: "space-y-6", children: [(0, jsx_runtime_1.jsx)("div", { className: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4", children: thresholdFields.map(({ key, label, description }) => ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: key, children: label }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: key, name: key, type: "number", min: "0", max: "100", value: formData[key], onChange: handleInputChange }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-muted-foreground", children: description })] }, key))) }), (0, jsx_runtime_1.jsx)("div", { className: "pt-4 border-t", children: (0, jsx_runtime_1.jsxs)(ui_1.Button, { type: "submit", disabled: isSubmitting, children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Save, { className: "h-4 w-4 mr-2" }), isSubmitting ? 'Saving...' : 'Save Thresholds'] }) })] })) })] }), (0, jsx_runtime_1.jsxs)(ui_1.Card, { children: [(0, jsx_runtime_1.jsx)(ui_1.CardHeader, { children: (0, jsx_runtime_1.jsx)(ui_1.CardTitle, { children: "Current Thresholds Summary" }) }), (0, jsx_runtime_1.jsx)(ui_1.CardContent, { children: (0, jsx_runtime_1.jsx)("div", { className: "space-y-2", children: thresholdFields.map(({ key, label }) => ((0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between items-center py-2 border-b last:border-0", children: [(0, jsx_runtime_1.jsx)("span", { className: "text-sm", children: label }), (0, jsx_runtime_1.jsx)("span", { className: "font-mono font-semibold", children: formData[key] })] }, key))) }) })] })] }));
};
exports.PolicyPage = PolicyPage;
