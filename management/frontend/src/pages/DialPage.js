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
const DialPage = () => {
    const { data: dialData, isLoading, error, setDial } = (0, useApi_1.useDial)();
    const [dialValue, setDialValue] = (0, react_1.useState)(0);
    const [reason, setReason] = (0, react_1.useState)('');
    const [isSubmitting, setIsSubmitting] = (0, react_1.useState)(false);
    const [submitError, setSubmitError] = (0, react_1.useState)(null);
    const [submitSuccess, setSubmitSuccess] = (0, react_1.useState)(false);
    const [isAcknowledging, setIsAcknowledging] = (0, react_1.useState)(false);
    react_1.default.useEffect(() => {
        if (dialData) {
            setDialValue(dialData.dial);
        }
    }, [dialData]);
    const handleAcknowledge = async () => {
        setIsAcknowledging(true);
        setSubmitError(null);
        try {
            await client_1.apiClient.post('/dial/acknowledge', { acknowledged: true });
            window.location.reload();
        }
        catch (err) {
            setSubmitError(err?.response?.data?.detail ?? 'Failed to acknowledge');
        }
        finally {
            setIsAcknowledging(false);
        }
    };
    const handleSetDial = async (e) => {
        e.preventDefault();
        setIsSubmitting(true);
        setSubmitError(null);
        setSubmitSuccess(false);
        try {
            await client_1.apiClient.put('/dial', { dial: dialValue, reason });
            setSubmitSuccess(true);
            setReason('');
            setTimeout(() => setSubmitSuccess(false), 3000);
        }
        catch (err) {
            setSubmitError(err?.response?.data?.detail ?? 'Failed to update dial');
        }
        finally {
            setIsSubmitting(false);
        }
    };
    const dialDescription = (v) => {
        if (v === 0)
            return 'Monitor only — no connections blocked';
        if (v <= 25)
            return 'Low — only very high-confidence threats blocked';
        if (v <= 50)
            return 'Medium — moderate threat level required to block';
        if (v <= 75)
            return 'High — aggressive blocking';
        return 'Maximum — strictest blocking';
    };
    return ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-6", children: [(0, jsx_runtime_1.jsx)("div", { className: "flex justify-between items-center", children: (0, jsx_runtime_1.jsx)("h1", { className: "text-2xl font-bold", children: "Blocking Dial" }) }), error && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsxs)(ui_1.AlertDescription, { children: ["Failed to load dial: ", error.message] })] })), submitError && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: submitError })] })), submitSuccess && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { children: [(0, jsx_runtime_1.jsx)(lucide_react_1.CheckCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: "Dial updated successfully." })] })), isLoading ? ((0, jsx_runtime_1.jsx)("div", { className: "text-center py-8", children: "Loading..." })) : ((0, jsx_runtime_1.jsxs)(jsx_runtime_1.Fragment, { children: [(0, jsx_runtime_1.jsxs)(ui_1.Card, { children: [(0, jsx_runtime_1.jsxs)(ui_1.CardHeader, { children: [(0, jsx_runtime_1.jsx)(ui_1.CardTitle, { children: "Current Dial Setting" }), (0, jsx_runtime_1.jsx)(ui_1.CardDescription, { children: "The dial controls how aggressively the proxy blocks traffic. 0 = monitor only, 100 = maximum blocking." })] }), (0, jsx_runtime_1.jsxs)(ui_1.CardContent, { children: [(0, jsx_runtime_1.jsxs)("div", { className: "text-5xl font-bold text-center py-4", children: [dialData?.dial ?? 0, (0, jsx_runtime_1.jsx)("span", { className: "text-lg text-muted-foreground", children: " / 100" })] }), (0, jsx_runtime_1.jsx)("p", { className: "text-center text-muted-foreground", children: dialDescription(dialData?.dial ?? 0) }), dialData?.blocking_acknowledged === false && dialData?.dial === 0 && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { className: "mt-4", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: "Blocking is not acknowledged. Acknowledge below before raising the dial above 0." })] }))] })] }), !dialData?.blocking_acknowledged && ((0, jsx_runtime_1.jsxs)(ui_1.Card, { children: [(0, jsx_runtime_1.jsxs)(ui_1.CardHeader, { children: [(0, jsx_runtime_1.jsx)(ui_1.CardTitle, { children: "Acknowledge Blocking Risk" }), (0, jsx_runtime_1.jsx)(ui_1.CardDescription, { children: "You must acknowledge that raising the dial above 0 will block real connections before proceeding." })] }), (0, jsx_runtime_1.jsx)(ui_1.CardContent, { children: (0, jsx_runtime_1.jsxs)(ui_1.Button, { onClick: handleAcknowledge, disabled: isAcknowledging, children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-4 w-4 mr-2" }), isAcknowledging ? 'Acknowledging...' : 'I understand — enable blocking'] }) })] })), (0, jsx_runtime_1.jsxs)(ui_1.Card, { children: [(0, jsx_runtime_1.jsxs)(ui_1.CardHeader, { children: [(0, jsx_runtime_1.jsx)(ui_1.CardTitle, { children: "Update Dial" }), (0, jsx_runtime_1.jsx)(ui_1.CardDescription, { children: "Set the dial to 0 at any time to return to monitor-only mode immediately. Changes above 0 require acknowledgment and are rate-limited (max 10/hour)." })] }), (0, jsx_runtime_1.jsx)(ui_1.CardContent, { children: (0, jsx_runtime_1.jsxs)("form", { onSubmit: handleSetDial, className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: "dial-value", children: "Dial Value (0\u2013100)" }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "dial-value", type: "number", min: 0, max: 100, value: dialValue, onChange: (e) => setDialValue(parseInt(e.target.value) || 0), className: "w-32" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-muted-foreground", children: dialDescription(dialValue) })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: "reason", children: "Reason (optional)" }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "reason", value: reason, onChange: (e) => setReason(e.target.value), placeholder: "e.g., Responding to active attack campaign" })] }), (0, jsx_runtime_1.jsx)(ui_1.Button, { type: "submit", disabled: isSubmitting || (dialValue > 0 && !dialData?.blocking_acknowledged), children: isSubmitting ? 'Updating...' : 'Set Dial' })] }) })] })] }))] }));
};
exports.DialPage = DialPage;
