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
        ban_threshold: config?.ban_threshold || 10,
        fingerprint_threshold: config?.fingerprint_threshold || 5,
        cidr_threshold: config?.cidr_threshold || 3,
    });
    const [isSubmitting, setIsSubmitting] = (0, react_1.useState)(false);
    const [submitError, setSubmitError] = (0, react_1.useState)(null);
    const [submitSuccess, setSubmitSuccess] = (0, react_1.useState)(false);
    // Update form data when config loads
    react_1.default.useEffect(() => {
        if (config) {
            setFormData({
                ban_threshold: config.ban_threshold,
                fingerprint_threshold: config.fingerprint_threshold,
                cidr_threshold: config.cidr_threshold,
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
            setSubmitError('Failed to update configuration. Please try again.');
        }
        finally {
            setIsSubmitting(false);
        }
    };
    return ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-6", children: [(0, jsx_runtime_1.jsx)("div", { className: "flex justify-between items-center", children: (0, jsx_runtime_1.jsx)("h1", { className: "text-2xl font-bold", children: "Policy Configuration" }) }), error && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsxs)(ui_1.AlertDescription, { children: ["Failed to load configuration: ", error.message] })] })), submitError && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: submitError })] })), submitSuccess && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "success", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: "Configuration updated successfully!" })] })), (0, jsx_runtime_1.jsxs)(ui_1.Card, { children: [(0, jsx_runtime_1.jsxs)(ui_1.CardHeader, { children: [(0, jsx_runtime_1.jsx)(ui_1.CardTitle, { children: "Threshold Configuration" }), (0, jsx_runtime_1.jsx)(ui_1.CardDescription, { children: "Configure the detection thresholds for automatic blocking" })] }), (0, jsx_runtime_1.jsx)(ui_1.CardContent, { children: isLoading ? ((0, jsx_runtime_1.jsx)("div", { className: "text-center py-8", children: "Loading configuration..." })) : ((0, jsx_runtime_1.jsx)("form", { onSubmit: handleSubmit, className: "space-y-6", children: (0, jsx_runtime_1.jsxs)("div", { className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "grid grid-cols-1 md:grid-cols-3 gap-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: "ban_threshold", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "Ban Threshold" })] }) }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "ban_threshold", name: "ban_threshold", type: "number", min: "1", value: formData.ban_threshold, onChange: handleInputChange }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-muted-foreground", children: "Number of detections before automatic IP ban" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: "fingerprint_threshold", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Fingerprint, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "Fingerprint Threshold" })] }) }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "fingerprint_threshold", name: "fingerprint_threshold", type: "number", min: "1", value: formData.fingerprint_threshold, onChange: handleInputChange }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-muted-foreground", children: "Number of fingerprint matches before action" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: "cidr_threshold", children: (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Network, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "CIDR Threshold" })] }) }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "cidr_threshold", name: "cidr_threshold", type: "number", min: "1", value: formData.cidr_threshold, onChange: handleInputChange }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-muted-foreground", children: "Number of CIDR matches before blocking" })] })] }), (0, jsx_runtime_1.jsx)("div", { className: "pt-4 border-t", children: (0, jsx_runtime_1.jsxs)(ui_1.Button, { type: "submit", disabled: isSubmitting, children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Save, { className: "h-4 w-4 mr-2" }), isSubmitting ? 'Saving...' : 'Save Configuration'] }) })] }) })) })] }), (0, jsx_runtime_1.jsxs)(ui_1.Card, { children: [(0, jsx_runtime_1.jsx)(ui_1.CardHeader, { children: (0, jsx_runtime_1.jsx)(ui_1.CardTitle, { children: "Current Policy Summary" }) }), (0, jsx_runtime_1.jsxs)(ui_1.CardContent, { children: [(0, jsx_runtime_1.jsxs)("div", { className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between items-center py-2 border-b", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "Automatic Bans" })] }), (0, jsx_runtime_1.jsxs)("span", { className: "font-mono", children: [formData.ban_threshold, " detections"] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between items-center py-2 border-b", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Fingerprint, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "Fingerprint Detection" })] }), (0, jsx_runtime_1.jsxs)("span", { className: "font-mono", children: [formData.fingerprint_threshold, " matches"] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between items-center py-2 border-b", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Network, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { children: "CIDR Blocking" })] }), (0, jsx_runtime_1.jsxs)("span", { className: "font-mono", children: [formData.cidr_threshold, " matches"] })] })] }), (0, jsx_runtime_1.jsxs)("div", { className: "mt-6 p-4 bg-muted rounded-lg", children: [(0, jsx_runtime_1.jsx)("h3", { className: "font-semibold mb-2", children: "Policy Behavior" }), (0, jsx_runtime_1.jsxs)("ul", { className: "space-y-2 text-sm", children: [(0, jsx_runtime_1.jsxs)("li", { className: "flex items-start gap-2", children: [(0, jsx_runtime_1.jsx)("span", { className: "mt-1", children: "\u2022" }), (0, jsx_runtime_1.jsxs)("span", { children: ["IP addresses will be automatically banned after ", formData.ban_threshold, " malicious detections"] })] }), (0, jsx_runtime_1.jsxs)("li", { className: "flex items-start gap-2", children: [(0, jsx_runtime_1.jsx)("span", { className: "mt-1", children: "\u2022" }), (0, jsx_runtime_1.jsxs)("span", { children: ["TLS fingerprints will trigger actions after ", formData.fingerprint_threshold, " matches"] })] }), (0, jsx_runtime_1.jsxs)("li", { className: "flex items-start gap-2", children: [(0, jsx_runtime_1.jsx)("span", { className: "mt-1", children: "\u2022" }), (0, jsx_runtime_1.jsxs)("span", { children: ["CIDR blocks will be applied after ", formData.cidr_threshold, " network matches"] })] })] })] })] })] })] }));
};
exports.PolicyPage = PolicyPage;
