"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DashboardPage = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const useApi_1 = require("../hooks/useApi");
const lucide_react_1 = require("lucide-react");
const actionColor = (action) => {
    if (action === 'block' || action === 'ban')
        return 'bg-red-100 text-red-700';
    if (action === 'tarpit')
        return 'bg-orange-100 text-orange-700';
    if (action === 'flag' || action === 'rate_limit')
        return 'bg-yellow-100 text-yellow-700';
    return 'bg-green-100 text-green-700';
};
const DashboardPage = () => {
    const { events, isConnected } = (0, useApi_1.useSseEvents)();
    const { data: healthData } = (0, useApi_1.useHealth)();
    const { data: bansData } = (0, useApi_1.useBans)();
    const { data: cidrsData } = (0, useApi_1.useCIDRs)();
    const { data: fingerprintsData } = (0, useApi_1.useFingerprints)();
    const { data: dialData } = (0, useApi_1.useDial)();
    const activeBans = bansData?.filter(b => !b.expires_at || new Date(b.expires_at) > new Date()).length ?? 0;
    return ((0, jsx_runtime_1.jsxs)("div", { className: "flex flex-col h-full", children: [(0, jsx_runtime_1.jsxs)("div", { className: "mb-4 flex-shrink-0", children: [(0, jsx_runtime_1.jsx)("h1", { className: "text-lg font-semibold text-gray-900", children: "Dashboard" }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-gray-500 mt-0.5", children: "Live security overview" })] }), (0, jsx_runtime_1.jsx)("div", { className: "grid grid-cols-4 gap-3 mb-4 flex-shrink-0", children: [
                    { label: 'Active Bans', value: activeBans, icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-4 w-4" }), color: 'red' },
                    { label: 'CIDR Blocks', value: cidrsData?.length ?? 0, icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Users, { className: "h-4 w-4" }), color: 'purple' },
                    { label: 'JA4 Blacklist', value: fingerprintsData?.length ?? 0, icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Fingerprint, { className: "h-4 w-4" }), color: 'blue' },
                    { label: 'Dial', value: dialData?.dial ?? 0, icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Activity, { className: "h-4 w-4" }), color: dialData?.dial === 0 ? 'green' : 'orange' },
                ].map(({ label, value, icon, color }) => {
                    const colors = {
                        red: 'text-red-600 bg-red-50', purple: 'text-purple-600 bg-purple-50',
                        blue: 'text-blue-600 bg-blue-50', green: 'text-green-600 bg-green-50',
                        orange: 'text-orange-600 bg-orange-50',
                    };
                    return ((0, jsx_runtime_1.jsxs)("div", { className: "bg-white rounded-lg border border-gray-200 px-4 py-3 flex items-center gap-3", children: [(0, jsx_runtime_1.jsx)("div", { className: `rounded-lg p-2 ${colors[color]}`, children: icon }), (0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("p", { className: "text-xs text-gray-500", children: label }), (0, jsx_runtime_1.jsx)("p", { className: "text-xl font-bold text-gray-900 leading-tight", children: value })] })] }, label));
                }) }), (0, jsx_runtime_1.jsxs)("div", { className: "flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-3 gap-4", children: [(0, jsx_runtime_1.jsxs)("div", { className: "lg:col-span-2 bg-white rounded-lg border border-gray-200 flex flex-col min-h-0", children: [(0, jsx_runtime_1.jsxs)("div", { className: "px-4 py-3 border-b border-gray-100 flex items-center justify-between flex-shrink-0", children: [(0, jsx_runtime_1.jsx)("span", { className: "text-sm font-semibold text-gray-900", children: "Live Events" }), (0, jsx_runtime_1.jsxs)("span", { className: `flex items-center gap-1.5 text-xs font-medium ${isConnected ? 'text-green-600' : 'text-gray-400'}`, children: [isConnected ? (0, jsx_runtime_1.jsx)(lucide_react_1.Wifi, { className: "h-3 w-3" }) : (0, jsx_runtime_1.jsx)(lucide_react_1.WifiOff, { className: "h-3 w-3" }), isConnected ? 'Live' : 'Offline'] })] }), (0, jsx_runtime_1.jsx)("div", { className: "flex-1 min-h-0 overflow-y-auto", children: events.length === 0 ? ((0, jsx_runtime_1.jsxs)("div", { className: "flex flex-col items-center justify-center h-full text-gray-400 py-8", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.Activity, { className: "h-8 w-8 mb-2 opacity-40" }), (0, jsx_runtime_1.jsx)("p", { className: "text-sm", children: "No events yet" }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs mt-0.5", children: "Events appear here as connections arrive" })] })) : ((0, jsx_runtime_1.jsx)("div", { className: "divide-y divide-gray-50", children: events.slice(0, 50).map((event, i) => ((0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50", children: [(0, jsx_runtime_1.jsx)("span", { className: "text-xs text-gray-400 w-16 shrink-0 tabular-nums", children: new Date(event.timestamp).toLocaleTimeString() }), (0, jsx_runtime_1.jsx)("span", { className: `inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium shrink-0 ${actionColor(event.type)}`, children: event.type }), (0, jsx_runtime_1.jsx)("span", { className: "text-xs text-gray-600 truncate", children: event.data?.ip ?? event.data?.message ?? JSON.stringify(event.data).slice(0, 60) })] }, event.id ?? i))) })) })] }), (0, jsx_runtime_1.jsxs)("div", { className: "bg-white rounded-lg border border-gray-200 flex flex-col min-h-0", children: [(0, jsx_runtime_1.jsx)("div", { className: "px-4 py-3 border-b border-gray-100 flex-shrink-0", children: (0, jsx_runtime_1.jsx)("span", { className: "text-sm font-semibold text-gray-900", children: "System Status" }) }), (0, jsx_runtime_1.jsxs)("div", { className: "flex-1 p-4 space-y-3", children: [[
                                        {
                                            label: 'Overall',
                                            icon: (0, jsx_runtime_1.jsx)(lucide_react_1.HeartPulse, { className: "h-3.5 w-3.5 text-gray-400" }),
                                            value: healthData?.status ?? 'checking…',
                                            ok: healthData?.status === 'healthy',
                                        },
                                        {
                                            label: 'Redis',
                                            icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Activity, { className: "h-3.5 w-3.5 text-gray-400" }),
                                            value: healthData?.redis !== false ? 'connected' : 'error',
                                            ok: healthData?.redis !== false,
                                        },
                                        {
                                            label: 'Blocking',
                                            icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Shield, { className: "h-3.5 w-3.5 text-gray-400" }),
                                            value: dialData?.blocking_acknowledged ? `dial ${dialData.dial}` : 'monitor only',
                                            ok: true,
                                        },
                                        {
                                            label: 'Version',
                                            icon: (0, jsx_runtime_1.jsx)(lucide_react_1.Activity, { className: "h-3.5 w-3.5 text-gray-400" }),
                                            value: healthData?.version ?? '—',
                                            ok: true,
                                        },
                                    ].map(({ label, icon, value, ok }) => ((0, jsx_runtime_1.jsxs)("div", { className: "flex items-center justify-between", children: [(0, jsx_runtime_1.jsxs)("div", { className: "flex items-center gap-2 text-xs text-gray-500", children: [icon, label] }), (0, jsx_runtime_1.jsx)("span", { className: `text-xs font-medium px-2 py-0.5 rounded-full ${ok ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`, children: value })] }, label))), !isConnected && ((0, jsx_runtime_1.jsxs)("div", { className: "flex items-start gap-2 rounded-lg bg-yellow-50 border border-yellow-100 px-3 py-2", children: [(0, jsx_runtime_1.jsx)(lucide_react_1.AlertCircle, { className: "h-3.5 w-3.5 text-yellow-600 mt-0.5 shrink-0" }), (0, jsx_runtime_1.jsx)("p", { className: "text-xs text-yellow-700", children: "Live feed disconnected" })] }))] })] })] })] }));
};
exports.DashboardPage = DashboardPage;
