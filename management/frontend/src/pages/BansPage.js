"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BansPage = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const useApi_1 = require("../hooks/useApi");
const ui_1 = require("../components/ui");
const lucide_react_1 = require("lucide-react");
const date_fns_1 = require("date-fns");
const BansPage = () => {
    const { data: bans, isLoading, error, createBan, deleteBan } = (0, useApi_1.useBans)();
    const [isDialogOpen, setIsDialogOpen] = (0, react_1.useState)(false);
    const [newBan, setNewBan] = (0, react_1.useState)({
        ip: '',
        reason: '',
        expires_at: '',
    });
    const handleCreateBan = async () => {
        try {
            await createBan({
                ip: newBan.ip,
                reason: newBan.reason,
                expires_at: newBan.expires_at,
            });
            setIsDialogOpen(false);
            setNewBan({ ip: '', reason: '', expires_at: '' });
        }
        catch (err) {
            console.error('Failed to create ban:', err);
        }
    };
    const handleDeleteBan = async (ip) => {
        try {
            await deleteBan(ip);
        }
        catch (err) {
            console.error('Failed to delete ban:', err);
        }
    };
    const isBanExpired = (expiresAt) => {
        return new Date(expiresAt) < new Date();
    };
    return ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-6", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between items-center", children: [(0, jsx_runtime_1.jsx)("h1", { className: "text-2xl font-bold", children: "Ban Management" }), (0, jsx_runtime_1.jsxs)(ui_1.Dialog, { open: isDialogOpen, onOpenChange: setIsDialogOpen, children: [(0, jsx_runtime_1.jsx)(ui_1.DialogTrigger, { children: (0, jsx_runtime_1.jsxs)(ui_1.Button, { children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Plus, { className: "h-4 w-4 mr-2" }), "Add Ban"] }) }), (0, jsx_runtime_1.jsxs)(ui_1.DialogContent, { children: [(0, jsx_runtime_1.jsx)(ui_1.DialogHeader, { children: (0, jsx_runtime_1.jsx)(ui_1.DialogTitle, { children: "Add New Ban" }) }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-4 py-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: "ip", children: "IP Address" }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "ip", value: newBan.ip, onChange: (e) => setNewBan({ ...newBan, ip: e.target.value }), placeholder: "e.g., 192.168.1.100" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: "reason", children: "Reason" }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "reason", value: newBan.reason, onChange: (e) => setNewBan({ ...newBan, reason: e.target.value }), placeholder: "e.g., Malicious activity detected" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(ui_1.Label, { htmlFor: "expires_at", children: "Expiration Date" }), (0, jsx_runtime_1.jsx)(ui_1.Input, { id: "expires_at", type: "datetime-local", value: newBan.expires_at, onChange: (e) => setNewBan({ ...newBan, expires_at: e.target.value }) })] })] }), (0, jsx_runtime_1.jsx)(ui_1.Button, { onClick: handleCreateBan, className: "w-full", children: "Create Ban" })] })] })] }), error && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsxs)(ui_1.AlertDescription, { children: ["Failed to load bans: ", error.message] })] })), (0, jsx_runtime_1.jsxs)(ui_1.Card, { children: [(0, jsx_runtime_1.jsx)(ui_1.CardHeader, { children: (0, jsx_runtime_1.jsx)(ui_1.CardTitle, { children: "Active Bans" }) }), (0, jsx_runtime_1.jsx)(ui_1.CardContent, { children: isLoading ? ((0, jsx_runtime_1.jsx)("div", { className: "text-center py-8", children: "Loading bans..." })) : bans && bans.length > 0 ? ((0, jsx_runtime_1.jsxs)(ui_1.Table, { children: [(0, jsx_runtime_1.jsx)(ui_1.TableHeader, { children: (0, jsx_runtime_1.jsxs)(ui_1.TableRow, { children: [(0, jsx_runtime_1.jsx)(ui_1.TableHead, { children: "IP Address" }), (0, jsx_runtime_1.jsx)(ui_1.TableHead, { children: "Reason" }), (0, jsx_runtime_1.jsx)(ui_1.TableHead, { children: "Expires At" }), (0, jsx_runtime_1.jsx)(ui_1.TableHead, { children: "Status" }), (0, jsx_runtime_1.jsx)(ui_1.TableHead, { children: "Actions" })] }) }), (0, jsx_runtime_1.jsx)(ui_1.TableBody, { children: bans.map((ban) => ((0, jsx_runtime_1.jsxs)(ui_1.TableRow, { children: [(0, jsx_runtime_1.jsx)(ui_1.TableCell, { className: "font-medium", children: ban.ip }), (0, jsx_runtime_1.jsx)(ui_1.TableCell, { children: ban.reason }), (0, jsx_runtime_1.jsx)(ui_1.TableCell, { children: ban.expires_at ? (0, date_fns_1.format)(new Date(ban.expires_at), 'PPpp') : '—' }), (0, jsx_runtime_1.jsx)(ui_1.TableCell, { children: ban.expires_at && isBanExpired(ban.expires_at) ? ((0, jsx_runtime_1.jsx)("span", { className: "text-muted-foreground", children: "Expired" })) : ((0, jsx_runtime_1.jsx)("span", { className: "text-green-600", children: "Active" })) }), (0, jsx_runtime_1.jsx)(ui_1.TableCell, { children: (0, jsx_runtime_1.jsxs)(ui_1.Button, { variant: "ghost", size: "icon", onClick: () => handleDeleteBan(ban.ip), disabled: !!(ban.expires_at && isBanExpired(ban.expires_at)), children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Trash2, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { className: "sr-only", children: "Delete" })] }) })] }, ban.ip))) })] })) : ((0, jsx_runtime_1.jsxs)("div", { className: "text-center py-8 text-muted-foreground", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "mx-auto h-8 w-8 mb-2" }), (0, jsx_runtime_1.jsx)("p", { children: "No active bans found" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm", children: "Add a ban to protect your system" })] })) })] })] }));
};
exports.BansPage = BansPage;
