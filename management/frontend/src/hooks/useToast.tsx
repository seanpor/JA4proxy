"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useToast = void 0;
// Simple toast hook implementation
const react_1 = require("react");
const useToast = () => {
    const [toasts, setToasts] = (0, react_1.useState)([]);
    const toast = (props) => {
        setToasts((prev) => [...prev, props]);
        setTimeout(() => {
            setToasts((prev) => prev.slice(1));
        }, 5000);
    };
    const ToastComponent = () => className = "fixed bottom-4 right-4 space-y-2" >
        { toasts, : .map((toast, index) => key = { index }, className = {} `p-4 rounded-md shadow-lg ${toast.variant === 'destructive' ? 'bg-destructive text-destructive-foreground' :
                toast.variant === 'success' ? 'bg-green-500 text-white' :
                    'bg-background border'}`) }
        >
            className;
    "font-medium" > { toast, : .title } < /h3>
        < p;
    className = "text-sm" > { toast, : .description } < /p>
        < /div>;
};
exports.useToast = useToast;
/div>;
;
return { toast, ToastComponent };
;
