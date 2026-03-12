// Basic UI components - simplified for build compatibility
import React from 'react';

// Button component
export const Button = ({ children, className = '', ...props }: any) => (
  <button className={`px-4 py-2 rounded-md text-sm font-medium ${className}`} {...props}>
    {children}
  </button>
);

// Card components
export const Card = ({ children, className = '' }: any) => (
  <div className={`rounded-lg border bg-card text-card-foreground shadow-sm ${className}`}>
    {children}
  </div>
);

export const CardHeader = ({ children, className = '' }: any) => (
  <div className={`flex flex-col space-y-1.5 p-6 ${className}`}>
    {children}
  </div>
);

export const CardTitle = ({ children, className = '' }: any) => (
  <h3 className={`text-2xl font-semibold leading-none tracking-tight ${className}`}>
    {children}
  </h3>
);

export const CardDescription = ({ children, className = '' }: any) => (
  <p className={`text-sm text-muted-foreground ${className}`}>
    {children}
  </p>
);

export const CardContent = ({ children, className = '' }: any) => (
  <div className={`p-6 pt-0 ${className}`}>
    {children}
  </div>
);

export const CardFooter = ({ children, className = '' }: any) => (
  <div className={`flex items-center p-6 pt-0 ${className}`}>
    {children}
  </div>
);

// Input component
export const Input = ({ className = '', ...props }: any) => (
  <input
    className={`flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ${className}`}
    {...props}
  />
);

// Label component
export const Label = ({ children, className = '' }: any) => (
  <label className={`text-sm font-medium leading-none ${className}`}>
    {children}
  </label>
);

// Table components
export const Table = ({ children, className = '' }: any) => (
  <div className="relative w-full overflow-auto">
    <table className={`w-full caption-bottom text-sm ${className}`}>
      {children}
    </table>
  </div>
);

export const TableHeader = ({ children, className = '' }: any) => (
  <thead className={`border-b ${className}`}>
    {children}
  </thead>
);

export const TableBody = ({ children, className = '' }: any) => (
  <tbody className={`border-0 ${className}`}>
    {children}
  </tbody>
);

export const TableRow = ({ children, className = '' }: any) => (
  <tr className={`border-b ${className}`}>
    {children}
  </tr>
);

export const TableHead = ({ children, className = '' }: any) => (
  <th className={`h-12 px-4 text-left align-middle font-medium ${className}`}>
    {children}
  </th>
);

export const TableCell = ({ children, className = '' }: any) => (
  <td className={`p-4 align-middle ${className}`}>
    {children}
  </td>
);

// Alert components
export const Alert = ({ children, className = '', variant = 'default' }: any) => (
  <div className={`rounded-lg border p-4 ${className}`}>
    {children}
  </div>
);

export const AlertTitle = ({ children, className = '' }: any) => (
  <h5 className={`mb-1 font-medium leading-none tracking-tight ${className}`}>
    {children}
  </h5>
);

export const AlertDescription = ({ children, className = '' }: any) => (
  <div className={`text-sm ${className}`}>
    {children}
  </div>
);

// Dialog components
export const Dialog = ({ children, open = false, className = '' }: any) => (
  <div className={`fixed inset-0 z-50 flex items-center justify-center bg-black/50 ${open ? '' : 'hidden'} ${className}`}>
    {children}
  </div>
);

export const DialogContent = ({ children, className = '' }: any) => (
  <div className={`bg-background rounded-lg p-6 shadow-lg ${className}`}>
    {children}
  </div>
);

export const DialogHeader = ({ children, className = '' }: any) => (
  <div className={`flex flex-col space-y-1.5 text-center sm:text-left ${className}`}>
    {children}
  </div>
);

export const DialogTitle = ({ children, className = '' }: any) => (
  <h3 className={`text-lg font-semibold leading-none tracking-tight ${className}`}>
    {children}
  </h3>
);

export const DialogTrigger = ({ children, className = '' }: any) => (
  <button className={`inline-flex items-center justify-center rounded-md text-sm font-medium ${className}`}>
    {children}
  </button>
);

// Select components
export const Select = ({ children, className = '', ...props }: any) => (
  <select className={`flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ${className}`} {...props}>
    {children}
  </select>
);

export const SelectTrigger = ({ children, className = '' }: any) => (
  <button className={`flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm ${className}`}>
    {children}
  </button>
);

export const SelectContent = ({ children, className = '' }: any) => (
  <div className={`relative z-50 min-w-8rem overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md ${className}`}>
    {children}
  </div>
);

export const SelectItem = ({ children, className = '' }: any) => (
  <div className={`relative flex w-full cursor-default select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm ${className}`}>
    {children}
  </div>
);

// Textarea component
export const Textarea = ({ className = '', ...props }: any) => (
  <textarea
    className={`flex min-h-80px w-full rounded-md border border-input bg-background px-3 py-2 text-sm ${className}`}
    {...props}
  />
);

// Badge component
export const Badge = ({ children, className = '', variant = 'default' }: any) => (
  <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${className}`}>
    {children}
  </span>
);

// Switch component
export const Switch = ({ checked = false, onCheckedChange, className = '' }: any) => {
  const handleClick = () => {
    if (onCheckedChange) {
      onCheckedChange(!checked);
    }
  };
  
  return (
    <button
      className={`inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent ${checked ? 'bg-primary' : 'bg-input'} ${className}`}
      onClick={handleClick}
    />
  );
};

// Sheet components
export const Sheet = ({ children, open = false, className = '' }: any) => (
  <div className={`fixed inset-0 z-50 bg-black/50 ${open ? '' : 'hidden'} ${className}`}>
    {children}
  </div>
);

export const SheetContent = ({ children, className = '' }: any) => (
  <div className={`fixed inset-y-0 left-0 z-50 w-full bg-background shadow-lg sm-max-w-xs ${className}`}>
    {children}
  </div>
);

export const SheetTrigger = ({ children, className = '' }: any) => (
  <button className={`inline-flex items-center justify-center rounded-md text-sm font-medium ${className}`}>
    {children}
  </button>
);