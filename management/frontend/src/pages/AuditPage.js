"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuditPage = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const useApi_1 = require("../hooks/useApi");
const ui_1 = require("../components/ui");
const lucide_react_1 = require("lucide-react");
const date_fns_1 = require("date-fns");
const severityClass = (s) => {
    if (s === 'high')
        return 'bg-red-100 text-red-700';
    if (s === 'medium')
        return 'bg-yellow-100 text-yellow-700';
    if (s === 'low')
        return 'bg-blue-100 text-blue-700';
    return 'bg-gray-100 text-gray-600';
};
const AuditPage = () => {
    const [searchTerm, setSearchTerm] = (0, react_1.useState)('');
    const [severityFilter, setSeverityFilter] = (0, react_1.useState)('all');
    const { data, isLoading, error } = (0, useApi_1.useAuditLog)(1, 200);
    const filtered = (data?.items ?? []).filter(e => {
        const matchSearch = !searchTerm ||
            e.details?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            e.event_type?.toLowerCase().includes(searchTerm.toLowerCase());
        const matchSeverity = severityFilter === 'all' || e.severity === severityFilter;
        return matchSearch && matchSeverity;
    });
    return ((0, jsx_runtime_1.jsxs)("div", { className: "flex flex-col h-full", children: [(0, jsx_runtime_1.jsx)("div", { className: "flex items-center justify-between mb-4 flex-shrink-0", children: (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("h1", { className: "text-lg font-semibold text-gray-900", children: "Audit Log" }), (0, jsx_runtime_1.jsxs)("p", { className: "text-xs text-gray-500 mt-0.5", children: [data?.total ?? 0, " total events"] })] }) }), (0, jsx_runtime_1.jsxs)("div", { className: "flex gap-3 mb-3 flex-shrink-0", children: [(0, jsx_runtime_1.jsxs)("div", { className: "relative flex-1 max-w-xs", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Search, { className: "absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-400" }), (0, jsx_runtime_1.jsx)(ui_1.Input, { className: "pl-8 h-8 text-xs", placeholder: "Search events\u2026", value: searchTerm, onChange: e => setSearchTerm(e.target.value) })] }), (0, jsx_runtime_1.jsxs)("select", { value: severityFilter, onChange: (e) => setSeverityFilter(e.target.value), className: "h-8 rounded-md border border-gray-300 bg-white px-3 text-xs focus:outline-none focus:ring-2 focus:ring-blue-500", children: [(0, jsx_runtime_1.jsx)("option", { value: "all", children: "All severities" }), (0, jsx_runtime_1.jsx)("option", { value: "high", children: "High" }), (0, jsx_runtime_1.jsx)("option", { value: "medium", children: "Medium" }), (0, jsx_runtime_1.jsx)("option", { value: "low", children: "Low" }), (0, jsx_runtime_1.jsx)("option", { value: "info", children: "Info" })] })] }), error && ((0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", className: "mb-3 flex-shrink-0", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-4 w-4" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { children: error.message })] })), (0, jsx_runtime_1.jsx)("div", { className: "flex-1 min-h-0 rounded-lg border border-gray-200 bg-white overflow-hidden", children: isLoading ? ((0, jsx_runtime_1.jsx)("div", { className: "flex items-center justify-center h-full text-gray-400 text-sm", children: "Loading\u2026" })) : ((0, jsx_runtime_1.jsx)("div", { className: "h-full overflow-y-auto", children: (0, jsx_runtime_1.jsxs)("table", { className: "w-full text-sm", children: [(0, jsx_runtime_1.jsx)("thead", { className: "sticky top-0 bg-gray-50 z-10", children: (0, jsx_runtime_1.jsxs)("tr", { className: "border-b border-gray-200", children: [(0, jsx_runtime_1.jsx)("th", { className: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider w-40", children: "Time" }), (0, jsx_runtime_1.jsx)("th", { className: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider w-32", children: "Severity" }), (0, jsx_runtime_1.jsx)("th", { className: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider w-40", children: "Event" }), (0, jsx_runtime_1.jsx)("th", { className: "px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider", children: "Details" })] }) }), (0, jsx_runtime_1.jsx)("tbody", { className: "divide-y divide-gray-100", children: filtered.length === 0 ? ((0, jsx_runtime_1.jsx)("tr", { children: (0, jsx_runtime_1.jsxs)("td", { colSpan: 4, className: "py-16 text-center text-gray-400", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.FileText, { className: "h-8 w-8 mx-auto mb-2 opacity-30" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm", children: "No events found" })] }) })) : filtered.map((entry, i) => ((0, jsx_runtime_1.jsxs)("tr", { className: "hover:bg-gray-50 transition-colors", children: [(0, jsx_runtime_1.jsx)("td", { className: "px-4 py-3 text-xs text-gray-500 tabular-nums whitespace-nowrap", children: (0, date_fns_1.format)(new Date(entry.timestamp), 'dd MMM HH:mm:ss') }), (0, jsx_runtime_1.jsx)("td", { className: "px-4 py-3", children: (0, jsx_runtime_1.jsx)("span", { className: `inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${severityClass(entry.severity)}`, children: entry.severity }) }), (0, jsx_runtime_1.jsx)("td", { className: "px-4 py-3 font-mono text-xs text-gray-700", children: entry.event_type }), (0, jsx_runtime_1.jsx)("td", { className: "px-4 py-3 text-xs text-gray-600 max-w-md truncate", children: entry.details })] }, entry.id ?? i))) })] }) })) })] }));
};
exports.AuditPage = AuditPage;
