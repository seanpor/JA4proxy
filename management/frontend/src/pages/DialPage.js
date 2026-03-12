"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DialPage = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const useApi_1 = require("../hooks/useApi");
const ui_1 = require("../components/ui");
const lucide_react_1 = require("lucide-react");
const useToast_1 = require("../hooks/useToast");
const DialPage = () => {
    const { mutate: dial, isPending, error, data: result } = (0, useApi_1.useDial)();
    const [fingerprint, setFingerprint] = (0, react_1.useState)('');
    const [copied, setCopied] = (0, react_1.useState)(false);
    const { toast } = (0, useToast_1.useToast)();
    const handleDial = () => {
        if (!fingerprint.trim()) {
            toast('Error', 'Please enter a fingerprint', 'destructive');
            return;
        }
        dial(fingerprint);
    };
    const handleCopyResult = () => {
        if (result) {
            navigator.clipboard.writeText(JSON.stringify(result, null, 2));
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
            toast('Copied', 'Result copied to clipboard');
        }
    };
    return ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-6", children: [(0, jsx_runtime_1.jsx)("div", { className: "flex justify-between items-center", children: (0, jsx_runtime_1.jsx)("h1", { className: "text-2xl font-bold", children: "Counterfactual Testing" }) }), (0, jsx_runtime_1.jsxs)(ui_1.Card, { children: [(0, jsx_runtime_1.jsxs)(ui_1.CardHeader, { children: [(0, jsx_runtime_1.jsx)(ui_1.CardTitle, { children: "Test Fingerprint" }), (0, jsx_runtime_1.jsx)(ui_1.CardDescription, { children: "Enter a TLS fingerprint to test against the current policy rules" })] }), (0, jsx_runtime_1.jsxs)(ui_1.CardContent, { className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: "fingerprint", children: "TLS Fingerprint" }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "fingerprint", value: fingerprint, onChange: (e) => setFingerprint(e.target.value), placeholder: "e.g., 771a332b45a32e3b8c4d5e6f7a8b9c0d", className: "font-mono" })] }), (0, jsx_runtime_1.jsxs)(ui_1.Button, { onClick: handleDial, disabled: isPending, className: "w-full sm:w-auto", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Phone, { className: "h-4 w-4 mr-2" }), isPending ? 'Testing...' : 'Test Fingerprint'] }), error && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsxs)(ui_1.AlertDescription, { children: ["Failed to test fingerprint: ", error.message] })] }))] })] }), result && ((0, jsx_runtime_1.jsxs)(ui_1.Card, { children: [(0, jsx_runtime_1.jsxs)(ui_1.CardHeader, { children: [(0, jsx_runtime_1.jsx)(ui_1.CardTitle, { children: "Test Result" }), (0, jsx_runtime_1.jsx)(ui_1.CardDescription, { children: "Counterfactual analysis of the fingerprint against current rules" })] }), (0, jsx_runtime_1.jsxs)(ui_1.CardContent, { className: "space-y-4", children: [(0, jsx_runtime_1.jsx)("div", { className: "flex justify-end", children: (0, jsx_runtime_1.jsxs)(ui_1.Button, { variant: "outline", size: "sm", onClick: handleCopyResult, children: [copied ? ((0, jsx_runtime_1.jsx)(lucide_react_1.Check, { className: "h-4 w-4 mr-2" })) : ((0, jsx_runtime_1.jsx)(lucide_react_1.Copy, { className: "h-4 w-4 mr-2" })), copied ? 'Copied!' : 'Copy Result'] }) }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-4", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("h3", { className: "font-semibold mb-2", children: "Decision" }), (0, jsx_runtime_1.jsx)("div", { className: "p-4 border rounded-lg bg-muted", children: (0, jsx_runtime_1.jsx)("p", { className: "font-mono text-lg", children: result.decision || 'No decision data' }) })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("h3", { className: "font-semibold mb-2", children: "Rules Matched" }), (0, jsx_runtime_1.jsx)("div", { className: "p-4 border rounded-lg bg-muted", children: result.rules_matched && result.rules_matched.length > 0 ? ((0, jsx_runtime_1.jsx)("ul", { className: "list-disc list-inside space-y-1", children: result.rules_matched.map((rule, index) => ((0, jsx_runtime_1.jsx)("li", { className: "font-mono text-sm", children: rule.name || rule.id || `Rule ${index + 1}` }, index))) })) : ((0, jsx_runtime_1.jsx)("p", { className: "text-muted-foreground", children: "No rules matched" })) })] }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("h3", { className: "font-semibold mb-2", children: "Additional Data" }), (0, jsx_runtime_1.jsx)("div", { className: "p-4 border rounded-lg bg-muted", children: (0, jsx_runtime_1.jsx)(ui_1.Textarea, { value: JSON.stringify(result.additional_data || {}, null, 2), readOnly: true, className: "font-mono text-sm h-40" }) })] })] })] })] }))] }));
};
exports.DialPage = DialPage;
