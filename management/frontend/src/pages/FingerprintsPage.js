"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FingerprintsPage = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const useApi_1 = require("../hooks/useApi");
const Button_1 = require("../components/ui/Button");
const Card_1 = require("../components/ui/Card");
const Table_1 = require("../components/ui/Table");
const Input_1 = require("../components/ui/Input");
const Label_1 = require("../components/ui/Label");
const Dialog_1 = require("../components/ui/Dialog");
const Alert_1 = require("../components/ui/Alert");
const lucide_react_1 = require("lucide-react");
const date_fns_1 = require("date-fns");
const FingerprintsPage = () => {
    const { data: fingerprints, isLoading, error, createFingerprint, deleteFingerprint } = (0, useApi_1.useFingerprints)();
    const [isDialogOpen, setIsDialogOpen] = (0, react_1.useState)(false);
    const [newFingerprint, setNewFingerprint] = (0, react_1.useState)({
        fingerprint: '',
        tag: '',
    });
    const handleCreateFingerprint = async () => {
        try {
            await createFingerprint({
                fingerprint: newFingerprint.fingerprint,
                tag: newFingerprint.tag,
            });
            setIsDialogOpen(false);
            setNewFingerprint({ fingerprint: '', tag: '' });
        }
        catch (err) {
            console.error('Failed to create fingerprint:', err);
        }
    };
    const handleDeleteFingerprint = async (id) => {
        try {
            await deleteFingerprint(id);
        }
        catch (err) {
            console.error('Failed to delete fingerprint:', err);
        }
    };
    return ((0, jsx_runtime_1.jsxs)("div", { className: "space-y-6", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex justify-between items-center", children: [(0, jsx_runtime_1.jsx)("h1", { className: "text-2xl font-bold", children: "Fingerprint Management" }), (0, jsx_runtime_1.jsxs)(Dialog_1.Dialog, { open: isDialogOpen, onOpenChange: setIsDialogOpen, children: [(0, jsx_runtime_1.jsx)(Dialog_1.DialogTrigger, { asChild: true, children: (0, jsx_runtime_1.jsxs)(Button_1.Button, { children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Plus, { className: "h-4 w-4 mr-2" }), "Add Fingerprint"] }) }), (0, jsx_runtime_1.jsxs)(Dialog_1.DialogContent, { children: [(0, jsx_runtime_1.jsx)(Dialog_1.DialogHeader, { children: (0, jsx_runtime_1.jsx)(Dialog_1.DialogTitle, { children: "Add New Fingerprint" }) }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-4 py-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(Label_1.Label, { htmlFor: "fingerprint", children: "Fingerprint Hash" }), (0, jsx_runtime_1.jsx)(Input_1.Input, { id: "fingerprint", value: newFingerprint.fingerprint, onChange: (e) => setNewFingerprint({ ...newFingerprint, fingerprint: e.target.value }), placeholder: "e.g., 771a332b45a32e3b8c4d5e6f7a8b9c0d" })] }), (0, jsx_runtime_1.jsxs)("div", { className: "space-y-2", children: [(0, jsx_runtime_1.jsx)(Label_1.Label, { htmlFor: "tag", children: "Tag" }), (0, jsx_runtime_1.jsx)(Input_1.Input, { id: "tag", value: newFingerprint.tag, onChange: (e) => setNewFingerprint({ ...newFingerprint, tag: e.target.value }), placeholder: "e.g., tor_exit_node" })] })] }), (0, jsx_runtime_1.jsx)(Button_1.Button, { onClick: handleCreateFingerprint, className: "w-full", children: "Create Fingerprint" })] })] })] }), error && ((0, jsx_runtime_1.jsxs)(Alert_1.Alert, { variant: "destructive", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsxs)(Alert_1.AlertDescription, { children: ["Failed to load fingerprints: ", error.message] })] })), (0, jsx_runtime_1.jsxs)(Card_1.Card, { children: [(0, jsx_runtime_1.jsx)(Card_1.CardHeader, { children: (0, jsx_runtime_1.jsx)(Card_1.CardTitle, { children: "TLS Fingerprints" }) }), (0, jsx_runtime_1.jsx)(Card_1.CardContent, { children: isLoading ? ((0, jsx_runtime_1.jsx)("div", { className: "text-center py-8", children: "Loading fingerprints..." })) : fingerprints && fingerprints.length > 0 ? ((0, jsx_runtime_1.jsxs)(Table_1.Table, { children: [(0, jsx_runtime_1.jsx)(Table_1.TableHeader, { children: (0, jsx_runtime_1.jsxs)(Table_1.TableRow, { children: [(0, jsx_runtime_1.jsx)(Table_1.TableHead, { children: "Fingerprint" }), (0, jsx_runtime_1.jsx)(Table_1.TableHead, { children: "Tag" }), (0, jsx_runtime_1.jsx)(Table_1.TableHead, { children: "Created At" }), (0, jsx_runtime_1.jsx)(Table_1.TableHead, { children: "Actions" })] }) }), (0, jsx_runtime_1.jsx)(Table_1.TableBody, { children: fingerprints.map((fp) => ((0, jsx_runtime_1.jsxs)(Table_1.TableRow, { children: [(0, jsx_runtime_1.jsx)(Table_1.TableCell, { className: "font-mono font-medium max-w-[200px] truncate", children: fp.fingerprint }), (0, jsx_runtime_1.jsx)(Table_1.TableCell, { children: fp.tag }), (0, jsx_runtime_1.jsx)(Table_1.TableCell, { children: (0, date_fns_1.format)(new Date(fp.created_at), 'PPpp') }), (0, jsx_runtime_1.jsx)(Table_1.TableCell, { children: (0, jsx_runtime_1.jsxs)(Button_1.Button, { variant: "ghost", size: "icon", onClick: () => handleDeleteFingerprint(fp.id), children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Trash2, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)("span", { className: "sr-only", children: "Delete" })] }) })] }, fp.id))) })] })) : ((0, jsx_runtime_1.jsxs)("div", { className: "text-center py-8 text-muted-foreground", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Fingerprint, { className: "mx-auto h-8 w-8 mb-2" }), (0, jsx_runtime_1.jsx)("p", { children: "No fingerprints found" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm", children: "Add TLS fingerprints to detect specific clients" })] })) })] })] }));
};
exports.FingerprintsPage = FingerprintsPage;
