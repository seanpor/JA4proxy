import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api/client';

export const useAuth = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const navigate = useNavigate();

  // Check authentication status on initial load
  useEffect(() => {
    const checkAuth = async () => {
      const token = sessionStorage.getItem('ja4proxy_api_key');
      if (token) {
        try {
          await validateToken(token);
          setIsAuthenticated(true);
        } catch (error) {
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
  useEffect(() => {
    const interceptor = apiClient.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          console.error('Unauthorized access, logging out');
          logout();
          navigate('/login', { replace: true });
        }
        return Promise.reject(error);
      }
    );

    return () => {
      apiClient.interceptors.response.eject(interceptor);
    };
  }, [navigate]);

  const login = async (apiKey: string): Promise<void> => {
    try {
      // Test the API key by making a simple authenticated request
      await apiClient.get('/health/ready', {
        headers: {
          Authorization: `Bearer ${apiKey}`
        }
      });

      // If successful, store the token
      sessionStorage.setItem('ja4proxy_api_key', apiKey);
      setIsAuthenticated(true);
    } catch (error) {
      console.error('Login failed:', error);
      throw new Error('Invalid API key');
    }
  };

  const validateToken = async (token?: string): Promise<boolean> => {
    const apiKey = token || sessionStorage.getItem('ja4proxy_api_key');
    if (!apiKey) return false;

    try {
      await apiClient.get('/health/ready', {
        headers: {
          Authorization: `Bearer ${apiKey}`
        }
      });
      return true;
    } catch (error) {
      console.error('Token validation failed:', error);
      return false;
    }
  };

  const logout = (): void => {
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