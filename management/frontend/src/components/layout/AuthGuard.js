"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthGuard = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const react_router_dom_1 = require("react-router-dom");
const useAuth_1 = require("../../../hooks/useAuth");
const AuthGuard = ({ children }) => {
    const { isAuthenticated, validateToken } = (0, useAuth_1.useAuth)();
    const navigate = (0, react_router_dom_1.useNavigate)();
    (0, react_1.useEffect)(() => {
        const checkAuth = async () => {
            if (!isAuthenticated) {
                try {
                    const valid = await validateToken();
                    if (!valid) {
                        navigate('/login', { replace: true });
                    }
                }
                catch (error) {
                    console.error('Authentication validation failed:', error);
                    navigate('/login', { replace: true });
                }
            }
        };
        checkAuth();
    }, [isAuthenticated, navigate, validateToken]);
    if (!isAuthenticated) {
        return null; // or loading spinner
    }
    return children ? (0, jsx_runtime_1.jsx)(jsx_runtime_1.Fragment, { children: children }) : (0, jsx_runtime_1.jsx)(react_router_dom_1.Outlet, {});
};
exports.AuthGuard = AuthGuard;
