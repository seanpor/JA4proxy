"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SheetTrigger = exports.SheetContent = exports.Sheet = exports.Switch = exports.Badge = exports.Textarea = exports.SelectItem = exports.SelectContent = exports.SelectTrigger = exports.Select = exports.DialogTrigger = exports.DialogTitle = exports.DialogHeader = exports.DialogContent = exports.Dialog = exports.AlertDescription = exports.AlertTitle = exports.Alert = exports.TableCell = exports.TableHead = exports.TableRow = exports.TableBody = exports.TableHeader = exports.Table = exports.Label = exports.Input = exports.CardFooter = exports.CardContent = exports.CardDescription = exports.CardTitle = exports.CardHeader = exports.Card = exports.Button = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
// Button Component
const Button = ({ children, className = '', variant = 'default', size = 'default', disabled, ...props }) => {
    const base = 'inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50';
    const variants = {
        default: 'bg-primary text-white hover:bg-blue-700 shadow-sm',
        outline: 'border border-gray-300 bg-white text-gray-700 hover:bg-gray-50 shadow-sm',
        ghost: 'text-gray-600 hover:bg-gray-100 hover:text-gray-900',
        destructive: 'bg-red-600 text-white hover:bg-red-700 shadow-sm',
    };
    const sizes = {
        default: 'h-9 px-4 py-2',
        sm: 'h-8 px-3 text-xs',
        lg: 'h-11 px-8',
        icon: 'h-9 w-9',
    };
    return ((0, jsx_runtime_1.jsx)("button", { className: `${base} ${variants[variant]} ${sizes[size]} ${className}`, disabled: disabled, ...props, children: children }));
};
exports.Button = Button;
// Card Components
const Card = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `rounded-lg border border-gray-200 bg-white shadow-sm ${className}`, children: children }));
exports.Card = Card;
const CardHeader = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `flex flex-col space-y-1 p-6 pb-4 ${className}`, children: children }));
exports.CardHeader = CardHeader;
const CardTitle = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("h3", { className: `text-base font-semibold leading-none tracking-tight text-gray-900 ${className}`, children: children }));
exports.CardTitle = CardTitle;
const CardDescription = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("p", { className: `text-sm text-gray-500 ${className}`, children: children }));
exports.CardDescription = CardDescription;
const CardContent = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `p-6 pt-0 ${className}`, children: children }));
exports.CardContent = CardContent;
const CardFooter = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `flex items-center p-6 pt-0 ${className}`, children: children }));
exports.CardFooter = CardFooter;
// Input Component
const Input = ({ className = '', ...props }) => ((0, jsx_runtime_1.jsx)("input", { className: `flex h-9 w-full rounded-md border border-gray-300 bg-white px-3 py-1 text-sm shadow-sm placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:cursor-not-allowed disabled:opacity-50 ${className}`, ...props }));
exports.Input = Input;
// Label Component
const Label = ({ children, className = '', ...props }) => ((0, jsx_runtime_1.jsx)("label", { className: `text-sm font-medium text-gray-700 ${className}`, ...props, children: children }));
exports.Label = Label;
// Table Components
const Table = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: "relative w-full overflow-auto rounded-md border border-gray-200", children: (0, jsx_runtime_1.jsx)("table", { className: `w-full caption-bottom text-sm ${className}`, children: children }) }));
exports.Table = Table;
const TableHeader = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("thead", { className: `bg-gray-50 ${className}`, children: children }));
exports.TableHeader = TableHeader;
const TableBody = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("tbody", { className: `divide-y divide-gray-100 ${className}`, children: children }));
exports.TableBody = TableBody;
const TableRow = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("tr", { className: `hover:bg-gray-50 transition-colors ${className}`, children: children }));
exports.TableRow = TableRow;
const TableHead = ({ children, className = '', ...props }) => ((0, jsx_runtime_1.jsx)("th", { className: `px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider ${className}`, ...props, children: children }));
exports.TableHead = TableHead;
const TableCell = ({ children, className = '', ...props }) => ((0, jsx_runtime_1.jsx)("td", { className: `px-4 py-3 text-sm text-gray-700 ${className}`, ...props, children: children }));
exports.TableCell = TableCell;
const Alert = ({ children, className = '', variant = 'default' }) => {
    const variants = {
        default: 'bg-blue-50 border-blue-200 text-blue-800',
        destructive: 'bg-red-50 border-red-200 text-red-800',
        success: 'bg-green-50 border-green-200 text-green-800',
        warning: 'bg-yellow-50 border-yellow-200 text-yellow-800',
    };
    return ((0, jsx_runtime_1.jsx)("div", { className: `flex gap-3 rounded-lg border p-4 ${variants[variant]} ${className}`, children: children }));
};
exports.Alert = Alert;
const AlertTitle = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("h5", { className: `font-semibold text-sm ${className}`, children: children }));
exports.AlertTitle = AlertTitle;
const AlertDescription = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `text-sm ${className}`, children: children }));
exports.AlertDescription = AlertDescription;
const Dialog = ({ children, open = false, onOpenChange, className = '' }) => {
    if (!open)
        return null;
    return ((0, jsx_runtime_1.jsxs)("div", { className: `fixed inset-0 z-50 flex items-center justify-center ${className}`, onClick: (e) => { if (e.target === e.currentTarget)
            onOpenChange?.(false); }, children: [(0, jsx_runtime_1.jsx)("div", { className: "absolute inset-0 bg-black/50", onClick: () => onOpenChange?.(false) }), children] }));
};
exports.Dialog = Dialog;
const DialogContent = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `relative z-10 bg-white rounded-xl shadow-xl p-6 w-full max-w-md mx-4 ${className}`, children: children }));
exports.DialogContent = DialogContent;
const DialogHeader = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `mb-4 ${className}`, children: children }));
exports.DialogHeader = DialogHeader;
const DialogTitle = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("h3", { className: `text-lg font-semibold text-gray-900 ${className}`, children: children }));
exports.DialogTitle = DialogTitle;
const DialogTrigger = ({ children }) => ((0, jsx_runtime_1.jsx)(jsx_runtime_1.Fragment, { children: children }));
exports.DialogTrigger = DialogTrigger;
// Select Component
const Select = ({ children, className = '', ...props }) => ((0, jsx_runtime_1.jsx)("select", { className: `h-9 rounded-md border border-gray-300 bg-white px-3 py-1 text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent ${className}`, ...props, children: children }));
exports.Select = Select;
const SelectTrigger = ({ children, className = '', ...props }) => ((0, jsx_runtime_1.jsx)("button", { className: `flex h-9 w-full items-center justify-between rounded-md border border-gray-300 bg-white px-3 py-1 text-sm shadow-sm ${className}`, ...props, children: children }));
exports.SelectTrigger = SelectTrigger;
const SelectContent = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `relative z-50 min-w-[8rem] overflow-hidden rounded-md border border-gray-200 bg-white shadow-md ${className}`, children: children }));
exports.SelectContent = SelectContent;
const SelectItem = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `relative flex w-full cursor-default items-center py-1.5 pl-3 pr-2 text-sm hover:bg-gray-100 ${className}`, children: children }));
exports.SelectItem = SelectItem;
// Textarea Component
const Textarea = ({ className = '', ...props }) => ((0, jsx_runtime_1.jsx)("textarea", { className: `flex min-h-[80px] w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:cursor-not-allowed disabled:opacity-50 ${className}`, ...props }));
exports.Textarea = Textarea;
const Badge = ({ children, className = '', variant = 'default' }) => {
    const variants = {
        default: 'bg-blue-100 text-blue-800',
        outline: 'border border-gray-300 text-gray-600',
        destructive: 'bg-red-100 text-red-800',
        success: 'bg-green-100 text-green-800',
        warning: 'bg-yellow-100 text-yellow-800',
    };
    return ((0, jsx_runtime_1.jsx)("span", { className: `inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${variants[variant]} ${className}`, children: children }));
};
exports.Badge = Badge;
const Switch = ({ checked = false, onCheckedChange, disabled = false, className = '' }) => ((0, jsx_runtime_1.jsx)("button", { role: "switch", "aria-checked": checked, disabled: disabled, onClick: () => onCheckedChange?.(!checked), className: `relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 ${checked ? 'bg-blue-600' : 'bg-gray-300'} ${className}`, children: (0, jsx_runtime_1.jsx)("span", { className: `inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${checked ? 'translate-x-4' : 'translate-x-0'}` }) }));
exports.Switch = Switch;
// Sheet / Drawer — no longer used (AppShell handles its own mobile drawer)
const Sheet = ({ children }) => (0, jsx_runtime_1.jsx)(jsx_runtime_1.Fragment, { children: children });
exports.Sheet = Sheet;
const SheetContent = ({ children }) => (0, jsx_runtime_1.jsx)(jsx_runtime_1.Fragment, { children: children });
exports.SheetContent = SheetContent;
const SheetTrigger = ({ children, ...props }) => ((0, jsx_runtime_1.jsx)("button", { ...props, children: children }));
exports.SheetTrigger = SheetTrigger;
