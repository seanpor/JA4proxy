"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SheetTrigger = exports.SheetContent = exports.Sheet = exports.Switch = exports.Badge = exports.Textarea = exports.SelectItem = exports.SelectContent = exports.SelectTrigger = exports.Select = exports.DialogTrigger = exports.DialogTitle = exports.DialogHeader = exports.DialogContent = exports.Dialog = exports.AlertDescription = exports.AlertTitle = exports.Alert = exports.TableCell = exports.TableHead = exports.TableRow = exports.TableBody = exports.TableHeader = exports.Table = exports.Label = exports.Input = exports.CardFooter = exports.CardContent = exports.CardDescription = exports.CardTitle = exports.CardHeader = exports.Card = exports.Button = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
// Button Component
const Button = ({ children, className = '', variant = 'default', size = 'default', ...props }) => {
    const baseClasses = 'px-4 py-2 rounded-md text-sm font-medium';
    const variantClasses = {
        default: 'bg-primary text-primary-foreground hover:bg-primary/90',
        outline: 'border border-input hover:bg-accent hover:text-accent-foreground',
        ghost: 'hover:bg-accent hover:text-accent-foreground',
        destructive: 'bg-destructive text-destructive-foreground hover:bg-destructive/90'
    };
    const sizeClasses = {
        default: 'h-10 py-2 px-4',
        sm: 'h-9 px-3',
        lg: 'h-11 px-8',
        icon: 'h-10 w-10'
    };
    return ((0, jsx_runtime_1.jsx)("button", { className: `${baseClasses} ${variantClasses[variant]} ${sizeClasses[size]} ${className}`, ...props, children: children }));
};
exports.Button = Button;
// Card Components
const Card = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `rounded-lg border bg-card text-card-foreground shadow-sm ${className}`, children: children }));
exports.Card = Card;
const CardHeader = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `flex flex-col space-y-1.5 p-6 ${className}`, children: children }));
exports.CardHeader = CardHeader;
const CardTitle = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("h3", { className: `text-2xl font-semibold leading-none tracking-tight ${className}`, children: children }));
exports.CardTitle = CardTitle;
const CardDescription = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("p", { className: `text-sm text-muted-foreground ${className}`, children: children }));
exports.CardDescription = CardDescription;
const CardContent = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `p-6 pt-0 ${className}`, children: children }));
exports.CardContent = CardContent;
const CardFooter = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `flex items-center p-6 pt-0 ${className}`, children: children }));
exports.CardFooter = CardFooter;
// Input Component
const Input = ({ className = '', ...props }) => ((0, jsx_runtime_1.jsx)("input", { className: `flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${className}`, ...props }));
exports.Input = Input;
// Label Component
const Label = ({ children, className = '', ...props }) => ((0, jsx_runtime_1.jsx)("label", { className: `text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 ${className}`, ...props, children: children }));
exports.Label = Label;
// Table Components
const Table = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: "relative w-full overflow-auto", children: (0, jsx_runtime_1.jsx)("table", { className: `w-full caption-bottom text-sm ${className}`, children: children }) }));
exports.Table = Table;
const TableHeader = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("thead", { className: `border-b ${className}`, children: children }));
exports.TableHeader = TableHeader;
const TableBody = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("tbody", { className: `border-0 ${className}`, children: children }));
exports.TableBody = TableBody;
const TableRow = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("tr", { className: `border-b ${className}`, children: children }));
exports.TableRow = TableRow;
const TableHead = ({ children, className = '', ...props }) => ((0, jsx_runtime_1.jsx)("th", { className: `h-12 px-4 text-left align-middle font-medium ${className}`, ...props, children: children }));
exports.TableHead = TableHead;
const TableCell = ({ children, className = '', ...props }) => ((0, jsx_runtime_1.jsx)("td", { className: `p-4 align-middle ${className}`, ...props, children: children }));
exports.TableCell = TableCell;
const Alert = ({ children, className = '', variant = 'default' }) => {
    const variantClasses = {
        default: 'bg-background',
        destructive: 'border-destructive/50 text-destructive',
        success: 'border-green-500 bg-green-50 text-green-800'
    };
    return ((0, jsx_runtime_1.jsx)("div", { className: `rounded-lg border p-4 ${variantClasses[variant]} ${className}`, children: children }));
};
exports.Alert = Alert;
const AlertTitle = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("h5", { className: `mb-1 font-medium leading-none tracking-tight ${className}`, children: children }));
exports.AlertTitle = AlertTitle;
const AlertDescription = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `text-sm ${className}`, children: children }));
exports.AlertDescription = AlertDescription;
const Dialog = ({ children, open = false, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `fixed inset-0 z-50 flex items-center justify-center bg-black/50 ${open ? '' : 'hidden'} ${className}`, children: children }));
exports.Dialog = Dialog;
const DialogContent = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `bg-background rounded-lg p-6 shadow-lg ${className}`, children: children }));
exports.DialogContent = DialogContent;
const DialogHeader = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `flex flex-col space-y-1.5 text-center sm:text-left ${className}`, children: children }));
exports.DialogHeader = DialogHeader;
const DialogTitle = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("h3", { className: `text-lg font-semibold leading-none tracking-tight ${className}`, children: children }));
exports.DialogTitle = DialogTitle;
const DialogTrigger = ({ children, className = '', ...props }) => ((0, jsx_runtime_1.jsx)("button", { className: `inline-flex items-center justify-center rounded-md text-sm font-medium ${className}`, ...props, children: children }));
exports.DialogTrigger = DialogTrigger;
// Select Components
const Select = ({ children, className = '', ...props }) => ((0, jsx_runtime_1.jsx)("select", { className: `flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ${className}`, ...props, children: children }));
exports.Select = Select;
const SelectTrigger = ({ children, className = '', ...props }) => ((0, jsx_runtime_1.jsx)("button", { className: `flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ${className}`, ...props, children: children }));
exports.SelectTrigger = SelectTrigger;
const SelectContent = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `relative z-50 min-w-[8rem] overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md ${className}`, children: children }));
exports.SelectContent = SelectContent;
const SelectItem = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `relative flex w-full cursor-default select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm ${className}`, children: children }));
exports.SelectItem = SelectItem;
// Textarea Component
const Textarea = ({ className = '', ...props }) => ((0, jsx_runtime_1.jsx)("textarea", { className: `flex min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${className}`, ...props }));
exports.Textarea = Textarea;
const Badge = ({ children, className = '', variant = 'default' }) => {
    const variantClasses = {
        default: 'border-transparent bg-primary text-primary-foreground',
        outline: 'border border-input',
        destructive: 'border-transparent bg-destructive text-destructive-foreground'
    };
    return ((0, jsx_runtime_1.jsx)("span", { className: `inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${variantClasses[variant]} ${className}`, children: children }));
};
exports.Badge = Badge;
const Switch = ({ checked = false, onCheckedChange, className = '', ...props }) => {
    const handleClick = () => {
        if (onCheckedChange) {
            onCheckedChange(!checked);
        }
    };
    return ((0, jsx_runtime_1.jsx)("button", { className: `inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent ${checked ? 'bg-primary' : 'bg-input'} ${className}`, onClick: handleClick, ...props }));
};
exports.Switch = Switch;
// Sheet Components
const Sheet = ({ children, open = false, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `fixed inset-0 z-50 bg-black/50 ${open ? '' : 'hidden'} ${className}`, children: children }));
exports.Sheet = Sheet;
const SheetContent = ({ children, className = '' }) => ((0, jsx_runtime_1.jsx)("div", { className: `fixed inset-y-0 left-0 z-50 w-full bg-background shadow-lg sm:max-w-xs ${className}`, children: children }));
exports.SheetContent = SheetContent;
const SheetTrigger = ({ children, className = '', ...props }) => ((0, jsx_runtime_1.jsx)("button", { className: `inline-flex items-center justify-center rounded-md text-sm font-medium ${className}`, ...props, children: children }));
exports.SheetTrigger = SheetTrigger;
