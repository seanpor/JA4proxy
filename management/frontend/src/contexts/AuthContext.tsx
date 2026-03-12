import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { apiClient } from '../api/client';

interface AuthContextValue {
  isAuthenticated: boolean;
  isLoading: boolean;
  username: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [username, setUsername] = useState<string | null>(null);

  // Validate stored token on mount
  useEffect(() => {
    const token = sessionStorage.getItem('ja4proxy_token');
    if (!token) {
      setIsLoading(false);
      return;
    }
    apiClient.get('/auth/me', { headers: { Authorization: `Bearer ${token}` } })
      .then(res => {
        apiClient.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        setUsername(res.data.username);
        setIsAuthenticated(true);
      })
      .catch(() => {
        sessionStorage.removeItem('ja4proxy_token');
      })
      .finally(() => setIsLoading(false));
  }, []);

  const login = useCallback(async (user: string, password: string) => {
    const res = await apiClient.post('/auth/login', { username: user, password });
    const { token, username: loggedInUser } = res.data;
    sessionStorage.setItem('ja4proxy_token', token);
    apiClient.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    setUsername(loggedInUser);
    setIsAuthenticated(true);
  }, []);

  const logout = useCallback(async () => {
    try { await apiClient.post('/auth/logout'); } catch { /* best effort */ }
    sessionStorage.removeItem('ja4proxy_token');
    apiClient.defaults.headers.common['Authorization'] = '';
    setUsername(null);
    setIsAuthenticated(false);
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, isLoading, username, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextValue => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
};
