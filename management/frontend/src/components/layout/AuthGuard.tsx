import React, { useEffect } from 'react';
import { useNavigate, Outlet } from 'react-router-dom';
import { useAuth } from '../../../hooks/useAuth';

interface AuthGuardProps {
  children?: React.ReactNode;
}

export const AuthGuard: React.FC<AuthGuardProps> = ({ children }) => {
  const { isAuthenticated, validateToken } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const checkAuth = async () => {
      if (!isAuthenticated) {
        try {
          const valid = await validateToken();
          if (!valid) {
            navigate('/login', { replace: true });
          }
        } catch (error) {
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

  return children ? <>{children}</> : <Outlet />;
};