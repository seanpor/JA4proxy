"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConfigPage = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const ui_1 = require("../components/ui");
const lucide_react_1 = require("lucide-react");
const useApi_1 = require("../hooks/useApi");
const FLAG_EMOJI = {
    CN: '🇨🇳', RU: '🇷🇺', KP: '🇰🇵', IR: '🇮🇷', BY: '🇧🇾',
    SY: '🇸🇾', CU: '🇨🇺', VE: '🇻🇪', MM: '🇲🇲', AF: '🇦🇫',
    US: '🇺🇸', GB: '🇬🇧', DE: '🇩🇪', FR: '🇫🇷', JP: '🇯🇵',
};
const flag = (cc) => FLAG_EMOJI[cc] ?? '🏳';
const ConfigPage = () => {
    const { data: health, isLoading: healthLoading } = (0, useApi_1.useHealth)();
    const { data: countries, isLoading: countriesLoading, error: countriesError, addCountry, removeCountry, isAdding, } = (0, useApi_1.useCountryBlocklist)();
    const [newCountry, setNewCountry] = (0, react_1.useState)('');
    const [addError, setAddError] = (0, react_1.useState)(null);
    const [removeError, setRemoveError] = (0, react_1.useState)(null);
    const handleAdd = async () => {
        const cc = newCountry.trim().toUpperCase();
        if (!/^[A-Z]{2}$/.test(cc)) {
            setAddError('Enter a 2-letter ISO country code (e.g. CN, RU)');
            return;
        }
        if (countries?.includes(cc)) {
            setAddError(`${cc} is already blocked`);
            return;
        }
        try {
            setAddError(null);
            await addCountry(cc);
            setNewCountry('');
        }
        catch {
            setAddError('Failed to add country — check backend connection');
        }
    };
    const handleRemove = async (cc) => {
        try {
            setRemoveError(null);
            await removeCountry(cc);
        }
        catch {
            setRemoveError(`Failed to remove ${cc}`);
        }
    };
    const handleKey = (e) => {
        if (e.key === 'Enter')
            handleAdd();
    };
    // derive component status indicators
    const redisOk = health?.redis === true || health?.components?.redis === 'healthy';
    const overallOk = health?.status === 'healthy';
    return ((0, jsx_runtime_1.jsxs)("div", { className: "flex flex-col h-full", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex-shrink-0 flex items-center justify-between px-6 py-4 border-b bg-background", children: [(0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("h1", { className: "text-lg font-semibold", children: "System" }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-muted-foreground mt-0.5", children: "Runtime status \u00B7 Country geo-blocking" })] }), !healthLoading && ((0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-1.5", children: [overallOk ? ((0, jsx_runtime_1.jsx)(lucide_react_1.CheckCircle2, { className: "h-4 w-4 text-green-500" })) : ((0, jsx_runtime_1.jsx)(lucide_react_1.XCircle, { className: "h-4 w-4 text-red-500" })), (0, jsx_runtime_1.jsx)("span", { className: `text-sm font-medium ${overallOk ? 'text-green-600' : 'text-red-600'}`, children: overallOk ? 'Operational' : 'Degraded' })] }))] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex-1 min-h-0 overflow-y-auto px-6 py-4 space-y-4", children: [(0, jsx_runtime_1.jsx)("div", { className: "grid grid-cols-2 sm:grid-cols-4 gap-3", children: [
                            {
                                label: 'Proxy Engine',
                                ok: overallOk,
                                detail: healthLoading ? '…' : (overallOk ? 'Running' : 'Error'),
                                icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Server, { className: "h-4 w-4" }),
                            },
                            {
                                label: 'Redis',
                                ok: redisOk,
                                detail: healthLoading ? '…' : (redisOk ? 'Connected' : 'Error'),
                                icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Server, { className: "h-4 w-4" }),
                            },
                            {
                                label: 'Version',
                                ok: true,
                                detail: health?.version ?? '—',
                                icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Server, { className: "h-4 w-4" }),
                            },
                            {
                                label: 'Uptime',
                                ok: true,
                                detail: health?.uptime != null
                                    ? `${Math.floor(health.uptime / 3600)}h ${Math.floor((health.uptime % 3600) / 60)}m`
                                    : '—',
                                icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Server, { className: "h-4 w-4" }),
                            },
                        ].map(({ label, ok, detail }) => ((0, jsx_runtime_1.jsxs)("div", { className: "rounded-lg border bg-card px-4 py-3 flex flex-col gap-1", children: [(0, jsx_runtime_1.jsx)("span", { className: "text-xs text-muted-foreground", children: label }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-1.5", children: [(0, jsx_runtime_1.jsx)("span", { className: `inline-block h-2 w-2 rounded-full flex-shrink-0 ${ok ? 'bg-green-500' : 'bg-red-500'}` }), (0, jsx_runtime_1.jsx)("span", { className: "text-sm font-semibold truncate", children: detail })] })] }, label))) }), (0, jsx_runtime_1.jsxs)("div", { className: "rounded-lg border bg-card overflow-hidden", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between px-4 py-3 border-b bg-muted/30", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Globe, { className: "h-4 w-4 text-muted-foreground" }), (0, jsx_runtime_1.jsx)("span", { className: "text-sm font-semibold", children: "Country Geo-Block" }), !countriesLoading && ((0, jsx_runtime_1.jsxs)(ui_1.Badge, { variant: "outline", className: "text-xs", children: [countries?.length ?? 0, " blocked"] }))] }), (0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2", children: [(0, jsx_runtime_1.jsx)("input", { type: "text", value: newCountry, onChange: e => setNewCountry(e.target.value.toUpperCase().slice(0, 2)), onKeyDown: handleKey, placeholder: "CC", maxLength: 2, className: "w-14 rounded border border-input bg-background px-2 py-1 text-sm font-mono text-center uppercase focus:outline-none focus:ring-1 focus:ring-ring" }), (0, jsx_runtime_1.jsxs)("button", { onClick: handleAdd, disabled: isAdding || !newCountry, className: "inline-flex items-center gap-1 rounded border border-input bg-background px-3 py-1 text-sm hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed transition-colors", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Plus, { className: "h-3.5 w-3.5" }), isAdding ? 'Adding…' : 'Block country'] })] })] }), addError && ((0, jsx_runtime_1.jsx)("div", { className: "px-4 py-2 bg-red-50 border-b border-red-100", children: (0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", className: "py-1 border-0 bg-transparent", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-3.5 w-3.5" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { className: "text-xs", children: addError })] }) })), removeError && ((0, jsx_runtime_1.jsx)("div", { className: "px-4 py-2 bg-red-50 border-b border-red-100", children: (0, jsx_runtime_1.jsxs)(ui_1.Alert, { variant: "destructive", className: "py-1 border-0 bg-transparent", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-3.5 w-3.5" }), (0, jsx_runtime_1.jsx)(ui_1.AlertDescription, { className: "text-xs", children: removeError })] }) })), countriesLoading ? ((0, jsx_runtime_1.jsx)("div", { className: "px-4 py-8 text-center text-sm text-muted-foreground", children: "Loading\u2026" })) : countriesError ? ((0, jsx_runtime_1.jsx)("div", { className: "px-4 py-8 text-center text-sm text-red-500", children: "Failed to load country blocklist" })) : !countries || countries.length === 0 ? ((0, jsx_runtime_1.jsxs)("div", { className: "px-4 py-10 text-center", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Globe, { className: "h-8 w-8 text-muted-foreground/40 mx-auto mb-2" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm text-muted-foreground", children: "No countries blocked" }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-muted-foreground mt-1", children: "Enter a 2-letter ISO code above to add one" })] })) : ((0, jsx_runtime_1.jsxs)("table", { className: "w-full text-sm", children: [(0, jsx_runtime_1.jsx)("thead", { className: "bg-muted/20 text-xs text-muted-foreground", children: (0, jsx_runtime_1.jsxs)("tr", { children: [(0, jsx_runtime_1.jsx)("th", { className: "text-left px-4 py-2 font-medium", children: "Country" }), (0, jsx_runtime_1.jsx)("th", { className: "text-left px-4 py-2 font-medium", children: "Code" }), (0, jsx_runtime_1.jsx)("th", { className: "text-left px-4 py-2 font-medium", children: "Effect" }), (0, jsx_runtime_1.jsx)("th", { className: "px-4 py-2" })] }) }), (0, jsx_runtime_1.jsx)("tbody", { className: "divide-y divide-border", children: [...countries].sort().map(cc => ((0, jsx_runtime_1.jsxs)("tr", { className: "hover:bg-muted/20 transition-colors", children: [(0, jsx_runtime_1.jsxs)("td", { className: "px-4 py-2.5 font-mono", children: [(0, jsx_runtime_1.jsx)("span", { className: "mr-2 text-base", children: flag(cc) }), cc] }), (0, jsx_runtime_1.jsx)("td", { className: "px-4 py-2.5 text-muted-foreground", children: "ISO 3166-1 alpha-2" }), (0, jsx_runtime_1.jsx)("td", { className: "px-4 py-2.5", children: (0, jsx_runtime_1.jsx)(ui_1.Badge, { variant: "destructive", className: "text-xs", children: "Hard block" }) }), (0, jsx_runtime_1.jsx)("td", { className: "px-4 py-2.5 text-right", children: (0, jsx_runtime_1.jsxs)("button", { onClick: () => handleRemove(cc), className: "inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-muted-foreground hover:text-red-600 hover:bg-red-50 transition-colors", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Trash2, { className: "h-3.5 w-3.5" }), "Remove"] }) })] }, cc))) })] }))] }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-muted-foreground pb-2", children: "Country blocks use GeoIP lookup and are applied before the scoring pipeline \u2014 connections are RST'd immediately. Changes take effect on the next connection; no proxy restart required." })] })] }));
};
exports.ConfigPage = ConfigPage;
