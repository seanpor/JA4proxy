"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useAuth = exports.AuthProvider = void 0;
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const client_1 = require("../api/client");
const AuthContext = (0, react_1.createContext)(null);
const AuthProvider = ({ children }) => {
    const [isAuthenticated, setIsAuthenticated] = (0, react_1.useState)(false);
    const [isLoading, setIsLoading] = (0, react_1.useState)(true);
    const [username, setUsername] = (0, react_1.useState)(null);
    // Validate stored token on mount
    (0, react_1.useEffect)(() => {
        const token = sessionStorage.getItem('ja4proxy_token');
        if (!token) {
            setIsLoading(false);
            return;
        }
        client_1.apiClient.get('/auth/me', { headers: { Authorization: `Bearer ${token}` } })
            .then(res => {
            client_1.apiClient.defaults.headers.common['Authorization'] = `Bearer ${token}`;
            setUsername(res.data.username);
            setIsAuthenticated(true);
        })
            .catch(() => {
            sessionStorage.removeItem('ja4proxy_token');
        })
            .finally(() => setIsLoading(false));
    }, []);
    const login = (0, react_1.useCallback)(async (user, password) => {
        const res = await client_1.apiClient.post('/auth/login', { username: user, password });
        const { token, username: loggedInUser } = res.data;
        sessionStorage.setItem('ja4proxy_token', token);
        client_1.apiClient.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        setUsername(loggedInUser);
        setIsAuthenticated(true);
    }, []);
    const logout = (0, react_1.useCallback)(async () => {
        try {
            await client_1.apiClient.post('/auth/logout');
        }
        catch { /* best effort */ }
        sessionStorage.removeItem('ja4proxy_token');
        client_1.apiClient.defaults.headers.common['Authorization'] = '';
        setUsername(null);
        setIsAuthenticated(false);
    }, []);
    return ((0, jsx_runtime_1.jsx)(AuthContext.Provider, { value: { isAuthenticated, isLoading, username, login, logout }, children: children }));
};
exports.AuthProvider = AuthProvider;
const useAuth = () => {
    const ctx = (0, react_1.useContext)(AuthContext);
    if (!ctx)
        throw new Error('useAuth must be used inside AuthProvider');
    return ctx;
};
exports.useAuth = useAuth;
