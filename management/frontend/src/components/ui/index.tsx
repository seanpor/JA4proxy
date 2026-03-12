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
  ...props
}) => {
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

  return (
    <button
      className={`${baseClasses} ${variantClasses[variant]} ${sizeClasses[size]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
};

// Card Components
export const Card: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`rounded-lg border bg-card text-card-foreground shadow-sm ${className}`}>
    {children}
  </div>
);

export const CardHeader: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`flex flex-col space-y-1.5 p-6 ${className}`}>
    {children}
  </div>
);

export const CardTitle: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <h3 className={`text-2xl font-semibold leading-none tracking-tight ${className}`}>
    {children}
  </h3>
);

export const CardDescription: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <p className={`text-sm text-muted-foreground ${className}`}>
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
    className={`flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
    {...props}
  />
);

// Label Component
export const Label: React.FC<React.LabelHTMLAttributes<HTMLLabelElement>> = ({ children, className = '', ...props }) => (
  <label
    className={`text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 ${className}`}
    {...props}
  >
    {children}
  </label>
);

// Table Components
export const Table: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className="relative w-full overflow-auto">
    <table className={`w-full caption-bottom text-sm ${className}`}>
      {children}
    </table>
  </div>
);

export const TableHeader: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <thead className={`border-b ${className}`}>
    {children}
  </thead>
);

export const TableBody: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <tbody className={`border-0 ${className}`}>
    {children}
  </tbody>
);

export const TableRow: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <tr className={`border-b ${className}`}>
    {children}
  </tr>
);

export const TableHead: React.FC<React.ThHTMLAttributes<HTMLTableCellElement>> = ({ children, className = '', ...props }) => (
  <th className={`h-12 px-4 text-left align-middle font-medium ${className}`} {...props}>
    {children}
  </th>
);

export const TableCell: React.FC<React.TdHTMLAttributes<HTMLTableCellElement>> = ({ children, className = '', ...props }) => (
  <td className={`p-4 align-middle ${className}`} {...props}>
    {children}
  </td>
);

// Alert Components
type AlertProps = ClassNameProps & {
  variant?: 'default' | 'destructive' | 'success';
};

export const Alert: React.FC<AlertProps> = ({ children, className = '', variant = 'default' }) => {
  const variantClasses = {
    default: 'bg-background',
    destructive: 'border-destructive/50 text-destructive',
    success: 'border-green-500 bg-green-50 text-green-800'
  };

  return (
    <div className={`rounded-lg border p-4 ${variantClasses[variant]} ${className}`}>
      {children}
    </div>
  );
};

export const AlertTitle: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <h5 className={`mb-1 font-medium leading-none tracking-tight ${className}`}>
    {children}
  </h5>
);

export const AlertDescription: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`text-sm ${className}`}>
    {children}
  </div>
);

// Dialog Components
type DialogProps = ClassNameProps & {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
};

export const Dialog: React.FC<DialogProps> = ({ children, open = false, className = '' }) => (
  <div className={`fixed inset-0 z-50 flex items-center justify-center bg-black/50 ${open ? '' : 'hidden'} ${className}`}>
    {children}
  </div>
);

export const DialogContent: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`bg-background rounded-lg p-6 shadow-lg ${className}`}>
    {children}
  </div>
);

export const DialogHeader: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`flex flex-col space-y-1.5 text-center sm:text-left ${className}`}>
    {children}
  </div>
);

export const DialogTitle: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <h3 className={`text-lg font-semibold leading-none tracking-tight ${className}`}>
    {children}
  </h3>
);

export const DialogTrigger: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement>> = ({ children, className = '', ...props }) => (
  <button className={`inline-flex items-center justify-center rounded-md text-sm font-medium ${className}`} {...props}>
    {children}
  </button>
);

// Select Components
export const Select: React.FC<React.SelectHTMLAttributes<HTMLSelectElement>> = ({ children, className = '', ...props }) => (
  <select className={`flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ${className}`} {...props}>
    {children}
  </select>
);

export const SelectTrigger: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement>> = ({ children, className = '', ...props }) => (
  <button className={`flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ${className}`} {...props}>
    {children}
  </button>
);

export const SelectContent: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`relative z-50 min-w-[8rem] overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md ${className}`}>
    {children}
  </div>
);

export const SelectItem: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`relative flex w-full cursor-default select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm ${className}`}>
    {children}
  </div>
);

// Textarea Component
export const Textarea: React.FC<React.TextareaHTMLAttributes<HTMLTextAreaElement>> = ({ className = '', ...props }) => (
  <textarea
    className={`flex min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
    {...props}
  />
);

// Badge Component
type BadgeProps = ClassNameProps & {
  variant?: 'default' | 'outline' | 'destructive';
};

export const Badge: React.FC<BadgeProps> = ({ children, className = '', variant = 'default' }) => {
  const variantClasses = {
    default: 'border-transparent bg-primary text-primary-foreground',
    outline: 'border border-input',
    destructive: 'border-transparent bg-destructive text-destructive-foreground'
  };

  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${variantClasses[variant]} ${className}`}>
      {children}
    </span>
  );
};

// Switch Component
type SwitchProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  checked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
};

export const Switch: React.FC<SwitchProps> = ({ checked = false, onCheckedChange, className = '', ...props }) => {
  const handleClick = () => {
    if (onCheckedChange) {
      onCheckedChange(!checked);
    }
  };

  return (
    <button
      className={`inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent ${checked ? 'bg-primary' : 'bg-input'} ${className}`}
      onClick={handleClick}
      {...props}
    />
  );
};

// Sheet Components
export const Sheet: React.FC<DialogProps> = ({ children, open = false, className = '' }) => (
  <div className={`fixed inset-0 z-50 bg-black/50 ${open ? '' : 'hidden'} ${className}`}>
    {children}
  </div>
);

export const SheetContent: React.FC<ClassNameProps> = ({ children, className = '' }) => (
  <div className={`fixed inset-y-0 left-0 z-50 w-full bg-background shadow-lg sm:max-w-xs ${className}`}>
    {children}
  </div>
);

export const SheetTrigger: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement>> = ({ children, className = '', ...props }) => (
  <button className={`inline-flex items-center justify-center rounded-md text-sm font-medium ${className}`} {...props}>
    {children}
  </button>
);