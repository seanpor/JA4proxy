// Simple toast hook implementation
import { useState } from 'react';

interface ToastProps {
  title: string;
  description: string;
  variant?: 'default' | 'destructive' | 'success';
}

export const useToast = () => {
  const [toasts, setToasts] = useState<ToastProps[]>([]);

  const toast = (props: ToastProps) => {
    setToasts((prev) => [...prev, props]);
    setTimeout(() => {
      setToasts((prev) => prev.slice(1));
    }, 5000);
  };

  const ToastComponent = () => (
    <div className="fixed bottom-4 right-4 space-y-2">
      {toasts.map((toast, index) => (
        <div
          key={index}
          className={`p-4 rounded-md shadow-lg ${
            toast.variant === 'destructive' ? 'bg-destructive text-destructive-foreground' :
            toast.variant === 'success' ? 'bg-green-500 text-white' :
            'bg-background border'
          }`}
        >
          <h3 className="font-medium">{toast.title}</h3>
          <p className="text-sm">{toast.description}</p>
        </div>
      ))}
    </div>
  );

  return { toast, ToastComponent };
};