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
const FIELDS = [
    { key: 'flag', label: 'Flag', color: 'text-blue-600', bg: 'bg-blue-50' },
    { key: 'rate_limit', label: 'Rate Limit', color: 'text-yellow-600', bg: 'bg-yellow-50' },
    { key: 'tarpit', label: 'Tarpit', color: 'text-orange-600', bg: 'bg-orange-50' },
    { key: 'block', label: 'Block', color: 'text-red-600', bg: 'bg-red-50' },
    { key: 'ban', label: 'Ban', color: 'text-red-900', bg: 'bg-red-100' },
];
const PolicyPage = () => {
    const { data: config, isLoading, error, updateThresholdConfig } = (0, useApi_1.useThresholdConfig)();
    const [form, setForm] = (0, react_1.useState)({ flag: 20, rate_limit: 35, tarpit: 55, block: 70, ban: 85 });
    const [isSubmitting, setIsSubmitting] = (0, react_1.useState)(false);
    const [feedback, setFeedback] = (0, react_1.useState)(null);
    react_1.default.useEffect(() => {
        if (config)
            setForm({ flag: config.flag, rate_limit: config.rate_limit, tarpit: config.tarpit, block: config.block, ban: config.ban });
    }, [config]);
    const handleSubmit = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        setFeedback(null);
        try {
            await updateThresholdConfig(form);
            setFeedback({ type: 'success', message: 'Thresholds saved' });
            setTimeout(() => setFeedback(null), 3000);
        }
        catch {
            setFeedback({ type: 'error', message: 'Thresholds must be in ascending order: flag ≤ rate_limit ≤ tarpit ≤ block ≤ ban' });
        }
        finally {
            setIsSubmitting(false);
        }
    };
    return ((0, jsx_runtime_1.jsxs)("div", { className: "flex flex-col h-full", children: [(0, jsx_runtime_1.jsxs)("div", { className: "mb-4 flex-shrink-0", children: [(0, jsx_runtime_1.jsx)("h1", { className: "text-lg font-semibold text-gray-900", children: "Policy" }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-gray-500 mt-0.5", children: "Risk score thresholds (0\u2013100). Connections scoring at or above each threshold trigger that action." })] }), isLoading ? ((0, jsx_runtime_1.jsx)("div", { className: "flex items-center justify-center flex-1 text-gray-400 text-sm", children: "Loading\u2026" })) : ((0, jsx_runtime_1.jsxs)("div", { className: "flex-1 min-h-0 overflow-y-auto", children: [(0, jsx_runtime_1.jsxs)("div", { className: "bg-white rounded-lg border border-gray-200 p-5 max-w-3xl", children: [error && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", className: "mb-4", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: error.message })] })), (0, jsx_runtime_1.jsxs)("form", { onSubmit: handleSubmit, children: [(0, jsx_runtime_1.jsx)("div", { className: "flex gap-1 h-6 rounded-full overflow-hidden mb-6", children: FIELDS.map(({ key, bg }) => ((0, jsx_runtime_1.jsx)("div", { className: `flex-1 ${bg} flex items-center justify-center`, title: `${form[key]}` }, key))) }), (0, jsx_runtime_1.jsx)("div", { className: "grid grid-cols-5 gap-4 mb-6", children: FIELDS.map(({ key, label, color, bg }) => ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-1", children: [(0, jsx_runtime_1.jsx)("div", { className: `inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${bg} ${color} mb-1`, children: label }), (0, jsx_runtime_1.jsx)(ui_1.Input, { type: "number", min: 0, max: 100, value: form[key], onChange: e => setForm(prev => ({ ...prev, [key]: parseInt(e.target.value) || 0 })), className: "text-center font-mono font-semibold" })] }, key))) }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-gray-400 mb-4", children: "Values must be ascending: flag \u2264 rate_limit \u2264 tarpit \u2264 block \u2264 ban" }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-3", children: [(0, jsx_runtime_1.jsxs)(ui_1.Button, { type: "submit", disabled: isSubmitting, children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Save, { className: "h-3.5 w-3.5 mr-1.5" }), isSubmitting ? 'Saving…' : 'Save Thresholds'] }), feedback?.type === 'success' && ((0, jsx_runtime_1.jsxs)("span", { className: "flex items-center gap-1 text-xs text-green-600", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.CheckCircle, { className: "h-3.5 w-3.5" }), feedback.message] }))] }), feedback?.type === 'error' && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", className: "mt-3", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: feedback.message })] }))] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "mt-4 max-w-3xl bg-gray-50 rounded-lg border border-gray-200 p-4", children: [(0, jsx_runtime_1.jsx)("p", { className: "text-xs font-medium text-gray-500 uppercase tracking-wider mb-3", children: "Score \u2192 Action reference" }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-1.5", children: [FIELDS.map(({ key, label, color }) => ((0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between text-xs", children: [(0, jsx_runtime_1.jsxs)("span", { className: "text-gray-500", children: ["Score \u2265 ", form[key]] }), (0, jsx_runtime_1.jsx)("span", { className: `font-medium ${color}`, children: label })] }, key))), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between text-xs border-t border-gray-200 pt-1.5 mt-1.5", children: [(0, jsx_runtime_1.jsxs)("span", { className: "text-gray-500", children: ["Score < ", form.flag] }), (0, jsx_runtime_1.jsx)("span", { className: "font-medium text-green-600", children: "Allow" })] })] })] })] }))] }));
};
exports.PolicyPage = PolicyPage;
