// Minimal toast notification hook without JSX
import { useState } from 'react';

export const useToast = () => {
  const [toasts, setToasts] = useState<Array<{
    id: number;
    title: string;
    description: string;
    variant: 'default' | 'destructive' | 'success';
  }>>([]);

  const toast = (title: string, description: string, variant: 'default' | 'destructive' | 'success' = 'default') => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, title, description, variant }]);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 5000);
  };

  return { toast, toasts };
};