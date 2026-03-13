// Clean UI Components - TypeScript compatible
import React from 'react';

// Basic types for component props
type ClassNameProps = {
  className?: string;
  children?: React.ReactNode;
};

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'outline' | 'ghost' | 'destructive';
  size?: 'default' | 'sm' | 'lg' | 'icon';
};

// Button Component
export const Button: React.FC<ButtonProps> = ({
  children,
  className = '',
  variant = 'default',
  size = 'default',
  disabled,
  ...props
}) => {
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
  return (
    <button
      className={`${base} ${variants[variant]} ${sizes[size]} ${className}`}
      disabled={disabled}
      {...props}
    >
      {children}
    </button>
  );
};

// Card Components
export const Card: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`rounded-lg border border-gray-200 bg-white shadow-sm ${className}`}>
    {children}
  </div>
);

export const CardHeader: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`flex flex-col space-y-1 p-6 pb-4 ${className}`}>
    {children}
  </div>
);

export const CardTitle: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <h3 className={`text-base font-semibold leading-none tracking-tight text-gray-900 ${className}`}>
    {children}
  </h3>
);

export const CardDescription: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <p className={`text-sm text-gray-500 ${className}`}>
    {children}
  </p>
);

export const CardContent: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`p-6 pt-0 ${className}`}>
    {children}
  </div>
);

export const CardFooter: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`flex items-center p-6 pt-0 ${className}`}>
    {children}
  </div>
);

// Input Component
export const Input: React.FC<React.InputHTMLAttributes<HTMLInputElement>> = ({ className = '', ...props }) => (
  <input
    className={`flex h-9 w-full rounded-md border border-gray-300 bg-white px-3 py-1 text-sm shadow-sm placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
    {...props}
  />
);

// Label Component
export const Label: React.FC<React.LabelHTMLAttributes<HTMLLabelElement>> = ({ children, className = '', ...props }) => (
  <label
    className={`text-sm font-medium text-gray-700 ${className}`}
    {...props}
  >
    {children}
  </label>
);

// Table Components
export const Table: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className="relative w-full overflow-auto rounded-md border border-gray-200">
    <table className={`w-full caption-bottom text-sm ${className}`}>
      {children}
    </table>
  </div>
);

export const TableHeader: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <thead className={`bg-gray-50 ${className}`}>
    {children}
  </thead>
);

export const TableBody: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <tbody className={`divide-y divide-gray-100 ${className}`}>
    {children}
  </tbody>
);

export const TableRow: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <tr className={`hover:bg-gray-50 transition-colors ${className}`}>
    {children}
  </tr>
);

export const TableHead: React.FC<React.ThHTMLAttributes<HTMLTableCellElement>> = ({ children, className = '', ...props }) => (
  <th className={`px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider ${className}`} {...props}>
    {children}
  </th>
);

export const TableCell: React.FC<React.TdHTMLAttributes<HTMLTableCellElement>> = ({ children, className = '', ...props }) => (
  <td className={`px-4 py-3 text-sm text-gray-700 ${className}`} {...props}>
    {children}
  </td>
);

// Alert Components
type AlertProps = ClassNameProps & {
  variant?: 'default' | 'destructive' | 'success' | 'warning';
};

export const Alert: React.FC<AlertProps> = ({ children, className = '', variant = 'default' }) => {
  const variants = {
    default: 'bg-blue-50 border-blue-200 text-blue-800',
    destructive: 'bg-red-50 border-red-200 text-red-800',
    success: 'bg-green-50 border-green-200 text-green-800',
    warning: 'bg-yellow-50 border-yellow-200 text-yellow-800',
  };
  return (
    <div className={`flex gap-3 rounded-lg border p-4 ${variants[variant]} ${className}`}>
      {children}
    </div>
  );
};

export const AlertTitle: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <h5 className={`font-semibold text-sm ${className}`}>{children}</h5>
);

export const AlertDescription: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`text-sm ${className}`}>{children}</div>
);

// Dialog Components
type DialogProps = ClassNameProps & {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
};

export const Dialog: React.FC<DialogProps> = ({ children, open = false, onOpenChange, className = '' }) => {
  if (!open) return null;
  return (
    <div
      className={`fixed inset-0 z-50 flex items-center justify-center ${className}`}
      onClick={(e) => { if (e.target === e.currentTarget) onOpenChange?.(false); }}
    >
      <div className="absolute inset-0 bg-black/50" onClick={() => onOpenChange?.(false)} />
      {children}
    </div>
  );
};

export const DialogContent: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`relative z-10 bg-white rounded-xl shadow-xl p-6 w-full max-w-md mx-4 ${className}`}>
    {children}
  </div>
);

export const DialogHeader: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`mb-4 ${className}`}>{children}</div>
);

export const DialogTitle: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <h3 className={`text-lg font-semibold text-gray-900 ${className}`}>{children}</h3>
);

export const DialogTrigger: React.FC<{ children?: React.ReactNode; asChild?: boolean }> = ({ children }) => (
  <>{children}</>
);

// Select Component
export const Select: React.FC<React.SelectHTMLAttributes<HTMLSelectElement>> = ({ children, className = '', ...props }) => (
  <select
    className={`h-9 rounded-md border border-gray-300 bg-white px-3 py-1 text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent ${className}`}
    {...props}
  >
    {children}
  </select>
);

export const SelectTrigger: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement>> = ({ children, className = '', ...props }) => (
  <button className={`flex h-9 w-full items-center justify-between rounded-md border border-gray-300 bg-white px-3 py-1 text-sm shadow-sm ${className}`} {...props}>
    {children}
  </button>
);

export const SelectContent: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`relative z-50 min-w-[8rem] overflow-hidden rounded-md border border-gray-200 bg-white shadow-md ${className}`}>
    {children}
  </div>
);

export const SelectItem: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`relative flex w-full cursor-default items-center py-1.5 pl-3 pr-2 text-sm hover:bg-gray-100 ${className}`}>
    {children}
  </div>
);

// Textarea Component
export const Textarea: React.FC<React.TextareaHTMLAttributes<HTMLTextAreaElement>> = ({ className = '', ...props }) => (
  <textarea
    className={`flex min-h-[80px] w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
    {...props}
  />
);

// Badge Component
type BadgeProps = ClassNameProps & {
  variant?: 'default' | 'outline' | 'destructive' | 'success' | 'warning';
};

export const Badge: React.FC<BadgeProps> = ({ children, className = '', variant = 'default' }) => {
  const variants = {
    default: 'bg-blue-100 text-blue-800',
    outline: 'border border-gray-300 text-gray-600',
    destructive: 'bg-red-100 text-red-800',
    success: 'bg-green-100 text-green-800',
    warning: 'bg-yellow-100 text-yellow-800',
  };
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${variants[variant]} ${className}`}>
      {children}
    </span>
  );
};

// Switch Component
type SwitchProps = {
  id?: string;
  name?: string;
  checked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
  disabled?: boolean;
  className?: string;
};

export const Switch: React.FC<SwitchProps> = ({ checked = false, onCheckedChange, disabled = false, className = '' }) => (
  <button
    role="switch"
    aria-checked={checked}
    disabled={disabled}
    onClick={() => onCheckedChange?.(!checked)}
    className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 ${checked ? 'bg-blue-600' : 'bg-gray-300'} ${className}`}
  >
    <span
      className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform ${checked ? 'translate-x-4' : 'translate-x-0'}`}
    />
  </button>
);

// Sheet / Drawer — no longer used (AppShell handles its own mobile drawer)
export const Sheet: React.FC<DialogProps> = ({ children }) => <>{children}</>;
export const SheetContent: React.FC<ClassNameProps> = ({ children }) => <>{children}</>;
export const SheetTrigger: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement>> = ({ children, ...props }) => (
  <button {...props}>{children}</button>
);
