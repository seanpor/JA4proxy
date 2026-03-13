"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CIDRsPage = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const useApi_1 = require("../hooks/useApi");
const ui_1 = require("../components/ui");
const lucide_react_1 = require("lucide-react");
const date_fns_1 = require("date-fns");
const CIDRsPage = () => {
    const { data: cidrs, isLoading, error, createCIDR, deleteCIDR } = (0, useApi_1.useCIDRs)();
    const [isDialogOpen, setIsDialogOpen] = (0, react_1.useState)(false);
    const [newCIDR, setNewCIDR] = (0, react_1.useState)({
        cidr: '',
        reason: '',
    });
    const handleCreateCIDR = async () => {
        try {
            await createCIDR({
                cidr: newCIDR.cidr,
                reason: newCIDR.reason,
            });
            setIsDialogOpen(false);
            setNewCIDR({ cidr: '', reason: '' });
        }
        catch (err) {
            console.error('Failed to create CIDR:', err);
        }
    };
    const handleDeleteCIDR = async (cidr) => {
        try {
            await deleteCIDR(cidr);
        }
        catch (err) {
            console.error('Failed to delete CIDR:', err);
        }
    };
    return ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-6", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between items-center", children: [(0, jsx_runtime_1.jsx)("h1", { className: "text-2xl font-bold", children: "CIDR Management" }), (0, jsx_runtime_1.jsxs)(ui_1.Dialog, { open: isDialogOpen, onOpenChange: setIsDialogOpen, children: [(0, jsx_runtime_1.jsx)(ui_1.DialogTrigger, { children: (0, jsx_runtime_1.jsxs)(ui_1.Button, { children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Plus, { className: "h-4 w-4 mr-2" }), "Add CIDR"] }) }), (0, jsx_runtime_1.jsxs)(ui_1.DialogContent, { children: [(0, jsx_runtime_1.jsx)(ui_1.DialogHeader, { children: (0, jsx_runtime_1.jsx)(ui_1.DialogTitle, { children: "Add New CIDR Block" }) }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-4 py-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: "cidr", children: "CIDR Notation" }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "cidr", value: newCIDR.cidr, onChange: (e) => setNewCIDR({ ...newCIDR, cidr: e.target.value }), placeholder: "e.g., 192.168.1.0/24" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: "reason", children: "Reason" }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "reason", value: newCIDR.reason, onChange: (e) => setNewCIDR({ ...newCIDR, reason: e.target.value }), placeholder: "e.g., Known malicious network" })] })] }), (0, jsx_runtime_1.jsx)(ui_1.Button, { onClick: handleCreateCIDR, className: "w-full", children: "Create CIDR Block" })] })] })] }), error && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsxs)(ui_1.AlertDescription, { children: ["Failed to load CIDR blocks: ", error.message] })] })), (0, jsx_runtime_1.jsxs)(ui_1.Card, { children: [(0, jsx_runtime_1.jsx)(ui_1.CardHeader, { children: (0, jsx_runtime_1.jsx)(ui_1.CardTitle, { children: "CIDR Blocks" }) }), (0, jsx_runtime_1.jsx)(ui_1.CardContent, { children: isLoading ? ((0, jsx_runtime_1.jsx)("div", { className: "text-center py-8", children: "Loading CIDR blocks..." })) : cidrs && cidrs.length > 0 ? ((0, jsx_runtime_1.jsxs)(ui_1.Table, { children: [(0, jsx_runtime_1.jsx)(ui_1.TableHeader, { children: (0, jsx_runtime_1.jsxs)(ui_1.TableRow, { children: [(0, jsx_runtime_1.jsx)(ui_1.TableHead, { children: "CIDR" }), (0, jsx_runtime_1.jsx)(ui_1.TableHead, { children: "Reason" }), (0, jsx_runtime_1.jsx)(ui_1.TableHead, { children: "Created At" }), (0, jsx_runtime_1.jsx)(ui_1.TableHead, { children: "Actions" })] }) }), (0, jsx_runtime_1.jsx)(ui_1.TableBody, { children: cidrs.map((cidr) => ((0, jsx_runtime_1.jsxs)(ui_1.TableRow, { children: [(0, jsx_runtime_1.jsx)(ui_1.TableCell, { className: "font-medium", children: cidr.cidr }), (0, jsx_runtime_1.jsx)(ui_1.TableCell, { children: cidr.reason }), (0, jsx_runtime_1.jsx)(ui_1.TableCell, { children: cidr.created_at ? (0, date_fns_1.format)(new Date(cidr.created_at), 'PPpp') : '—' }), (0, jsx_runtime_1.jsx)(ui_1.TableCell, { children: (0, jsx_runtime_1.jsxs)(ui_1.Button, { variant: "ghost", size: "icon", onClick: () => handleDeleteCIDR(cidr.cidr), children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Trash2, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { className: "sr-only", children: "Delete" })] }) })] }, cidr.cidr))) })] })) : ((0, jsx_runtime_1.jsxs)("div", { className: "text-center py-8 text-muted-foreground", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Network, { className: "mx-auto h-8 w-8 mb-2" }), (0, jsx_runtime_1.jsx)("p", { children: "No CIDR blocks found" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm", children: "Add CIDR blocks to protect network ranges" })] })) })] })] }));
};
exports.CIDRsPage = CIDRsPage;
