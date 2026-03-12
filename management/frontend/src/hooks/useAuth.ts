import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api/client';

export const useAuth = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const navigate = useNavigate();

  // Validate stored session token on initial load
  useEffect(() => {
    const checkAuth = async () => {
      const token = sessionStorage.getItem('ja4proxy_token');
      if (token) {
        try {
          await apiClient.get('/auth/me', {
            headers: { Authorization: `Bearer ${token}` },
          });
          setIsAuthenticated(true);
        } catch {
          sessionStorage.removeItem('ja4proxy_token');
          setIsAuthenticated(false);
        }
      }
      setIsLoading(false);
    };
    checkAuth();
  }, []);

  // Redirect to login on any 401
  useEffect(() => {
    const interceptor = apiClient.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          sessionStorage.removeItem('ja4proxy_token');
          setIsAuthenticated(false);
          navigate('/login', { replace: true });
        }
        return Promise.reject(error);
      }
    );
    return () => apiClient.interceptors.response.eject(interceptor);
  }, [navigate]);

  const login = async (username: string, password: string): Promise<void> => {
    const response = await apiClient.post('/auth/login', { username, password });
    const { token } = response.data;
    sessionStorage.setItem('ja4proxy_token', token);
    apiClient.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    setIsAuthenticated(true);
  };

  const logout = async (): Promise<void> => {
    const token = sessionStorage.getItem('ja4proxy_token');
    if (token) {
      try {
        await apiClient.post('/auth/logout');
      } catch { /* best effort */ }
      sessionStorage.removeItem('ja4proxy_token');
    }
    apiClient.defaults.headers.common['Authorization'] = '';
    setIsAuthenticated(false);
    navigate('/login', { replace: true });
  };

  return { isAuthenticated, isLoading, login, logout };
};
