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
exports.DialPage = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = __importStar(require("react"));
const useApi_1 = require("../hooks/useApi");
const client_1 = require("../api/client");
const ui_1 = require("../components/ui");
const lucide_react_1 = require("lucide-react");
const dialLabel = (v) => {
    if (v === 0)
        return { text: 'Monitor only', color: 'text-green-600', bg: 'bg-green-50' };
    if (v <= 25)
        return { text: 'Low blocking', color: 'text-blue-600', bg: 'bg-blue-50' };
    if (v <= 50)
        return { text: 'Medium blocking', color: 'text-yellow-600', bg: 'bg-yellow-50' };
    if (v <= 75)
        return { text: 'High blocking', color: 'text-orange-600', bg: 'bg-orange-50' };
    return { text: 'Maximum blocking', color: 'text-red-600', bg: 'bg-red-50' };
};
const DialPage = () => {
    const { data: dialData, isLoading, error, setDial } = (0, useApi_1.useDial)();
    const [dialValue, setDialValue] = (0, react_1.useState)(0);
    const [reason, setReason] = (0, react_1.useState)('');
    const [isSubmitting, setIsSubmitting] = (0, react_1.useState)(false);
    const [isAcknowledging, setIsAcknowledging] = (0, react_1.useState)(false);
    const [feedback, setFeedback] = (0, react_1.useState)(null);
    react_1.default.useEffect(() => {
        if (dialData)
            setDialValue(dialData.dial);
    }, [dialData]);
    const handleAcknowledge = async () => {
        setIsAcknowledging(true);
        setFeedback(null);
        try {
            await client_1.apiClient.post('/dial/acknowledge', { acknowledged: true });
            window.location.reload();
        }
        catch (err) {
            setFeedback({ type: 'error', message: err?.response?.data?.detail ?? 'Failed to acknowledge' });
        }
        finally {
            setIsAcknowledging(false);
        }
    };
    const handleSetDial = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        setFeedback(null);
        try {
            await client_1.apiClient.put('/dial', { dial: dialValue, reason });
            setFeedback({ type: 'success', message: `Dial set to ${dialValue}` });
            setReason('');
        }
        catch (err) {
            setFeedback({ type: 'error', message: err?.response?.data?.detail ?? 'Failed to update dial' });
        }
        finally {
            setIsSubmitting(false);
        }
    };
    const current = dialData?.dial ?? 0;
    const label = dialLabel(current);
    const newLabel = dialLabel(dialValue);
    return ((0, jsx_runtime_1.jsxs)("div", { className: "flex flex-col h-full", children: [(0, jsx_runtime_1.jsxs)("div", { className: "mb-4 flex-shrink-0", children: [(0, jsx_runtime_1.jsx)("h1", { className: "text-lg font-semibold text-gray-900", children: "Blocking Dial" }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-gray-500 mt-0.5", children: "0 = monitor only, 100 = maximum blocking" })] }), isLoading ? ((0, jsx_runtime_1.jsx)("div", { className: "flex items-center justify-center flex-1 text-gray-400 text-sm", children: "Loading\u2026" })) : ((0, jsx_runtime_1.jsxs)("div", { className: "flex-1 min-h-0 overflow-y-auto", children: [(0, jsx_runtime_1.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-2 gap-5 max-w-3xl", children: [(0, jsx_runtime_1.jsxs)("div", { className: "bg-white rounded-lg border border-gray-200 p-5", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2 mb-4", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Activity, { className: "h-4 w-4 text-gray-400" }), (0, jsx_runtime_1.jsx)("span", { className: "text-sm font-medium text-gray-700", children: "Current State" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "text-center py-4", children: [(0, jsx_runtime_1.jsx)("div", { className: `inline-flex items-center justify-center w-24 h-24 rounded-full ${label.bg} mb-3`, children: (0, jsx_runtime_1.jsx)("span", { className: `text-4xl font-bold ${label.color}`, children: current }) }), (0, jsx_runtime_1.jsx)("p", { className: `text-sm font-medium ${label.color}`, children: label.text }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-gray-400 mt-1", children: dialData?.blocking_acknowledged ? 'Blocking acknowledged' : 'Not acknowledged' })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "bg-white rounded-lg border border-gray-200 p-5", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2 mb-4", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-4 w-4 text-gray-400" }), (0, jsx_runtime_1.jsx)("span", { className: "text-sm font-medium text-gray-700", children: "Set Dial" })] }), !dialData?.blocking_acknowledged && ((0, jsx_runtime_1.jsxs)("div", { className: "mb-4 p-3 rounded-lg bg-amber-50 border border-amber-200", children: [(0, jsx_runtime_1.jsx)("p", { className: "text-xs text-amber-700 mb-2", children: "You must acknowledge blocking risk before raising the dial above 0." }), (0, jsx_runtime_1.jsx)(ui_1.Button, { size: "sm", variant: "outline", onClick: handleAcknowledge, disabled: isAcknowledging, children: isAcknowledging ? 'Acknowledging…' : 'I understand — enable blocking' })] })), (0, jsx_runtime_1.jsxs)("form", { onSubmit: handleSetDial, className: "space-y-3", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: "dial-value", children: "Dial value (0\u2013100)" }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-3 mt-1", children: [(0, jsx_runtime_1.jsx)(ui_1.Input, { id: "dial-value", type: "number", min: 0, max: 100, value: dialValue, onChange: e => setDialValue(parseInt(e.target.value) || 0), className: "w-24" }), (0, jsx_runtime_1.jsx)("span", { className: `text-xs font-medium ${newLabel.color}`, children: newLabel.text })] })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: "reason", children: "Reason (optional)" }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "reason", className: "mt-1", value: reason, onChange: e => setReason(e.target.value), placeholder: "e.g. Active attack campaign" })] }), (0, jsx_runtime_1.jsx)(ui_1.Button, { type: "submit", disabled: isSubmitting || (dialValue > 0 && !dialData?.blocking_acknowledged), children: isSubmitting ? 'Updating…' : 'Set Dial' })] })] })] }), (error || feedback) && ((0, jsx_runtime_1.jsxs)("div", { className: "mt-4 max-w-3xl", children: [error && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: error.message })] })), feedback?.type === 'error' && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: feedback.message })] })), feedback?.type === 'success' && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "success", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.CheckCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: feedback.message })] }))] }))] }))] }));
};
exports.DialPage = DialPage;
