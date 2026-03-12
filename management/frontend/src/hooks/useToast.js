"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useToast = void 0;
// Minimal toast notification hook without JSX
const react_1 = require("react");
const useToast = () => {
    const [toasts, setToasts] = (0, react_1.useState)([]);
    const toast = (title, description, variant = 'default') => {
        const id = Date.now();
        setToasts(prev => [...prev, { id, title, description, variant }]);
        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            setToasts(prev => prev.filter(t => t.id !== id));
        }, 5000);
    };
    return { toast, toasts };
};
exports.useToast = useToast;
