"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.useAuth = void 0;
const react_1 = require("react");
const react_router_dom_1 = require("react-router-dom");
const client_1 = require("../api/client");
const useAuth = () => {
    const [isAuthenticated, setIsAuthenticated] = (0, react_1.useState)(false);
    const [isLoading, setIsLoading] = (0, react_1.useState)(true);
    const navigate = (0, react_router_dom_1.useNavigate)();
    // Check authentication status on initial load
    (0, react_1.useEffect)(() => {
        const checkAuth = async () => {
            const token = sessionStorage.getItem('ja4proxy_api_key');
            if (token) {
                try {
                    await validateToken(token);
                    setIsAuthenticated(true);
                }
                catch (error) {
                    console.error('Token validation failed:', error);
                    sessionStorage.removeItem('ja4proxy_api_key');
                    setIsAuthenticated(false);
                }
            }
            setIsLoading(false);
        };
        checkAuth();
    }, []);
    // Set up axios interceptors for 401 handling
    (0, react_1.useEffect)(() => {
        const interceptor = client_1.apiClient.interceptors.response.use((response) => response, (error) => {
            if (error.response?.status === 401) {
                console.error('Unauthorized access, logging out');
                logout();
                navigate('/login', { replace: true });
            }
            return Promise.reject(error);
        });
        return () => {
            client_1.apiClient.interceptors.response.eject(interceptor);
        };
    }, [navigate]);
    const login = async (apiKey) => {
        try {
            // Test the API key by making a simple authenticated request
            await client_1.apiClient.get('/health/ready', {
                headers: {
                    Authorization: `Bearer ${apiKey}`
                }
            });
            // If successful, store the token
            sessionStorage.setItem('ja4proxy_api_key', apiKey);
            setIsAuthenticated(true);
        }
        catch (error) {
            console.error('Login failed:', error);
            throw new Error('Invalid API key');
        }
    };
    const validateToken = async (token) => {
        const apiKey = token || sessionStorage.getItem('ja4proxy_api_key');
        if (!apiKey)
            return false;
        try {
            await client_1.apiClient.get('/health/ready', {
                headers: {
                    Authorization: `Bearer ${apiKey}`
                }
            });
            return true;
        }
        catch (error) {
            console.error('Token validation failed:', error);
            return false;
        }
    };
    const logout = () => {
        sessionStorage.removeItem('ja4proxy_api_key');
        setIsAuthenticated(false);
    };
    return {
        isAuthenticated,
        isLoading,
        login,
        validateToken,
        logout,
    };
};
exports.useAuth = useAuth;
