/* eslint-disable react-refresh/only-export-components */
import type { ReactNode } from 'react';
import { createContext, useContext, useState, useEffect } from 'react';
import type { User, MFAMethod, LoginResponse, RegisterResponse } from '../types';
import authService from '../services/authService';
import { tokenStorage } from '../services/api';

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string, returnUrl?: string) => Promise<{
    mfaRequired?: boolean;
    mfaToken?: string;
    availableMethods?: MFAMethod[];
    preferredMethod?: MFAMethod;
    returnUrl?: string;
  }>;
  register: (email: string, password: string) => Promise<RegisterResponse>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const isAuthenticated = !!user;

  // Check authentication on mount
  useEffect(() => {
    const checkAuth = async () => {
      const token = tokenStorage.getAccessToken();
      if (token) {
        try {
          const currentUser = await authService.getCurrentUser();
          setUser(currentUser);
        } catch {
          tokenStorage.clearTokens();
        }
      }
      setIsLoading(false);
    };

    checkAuth();
  }, []);

  const login = async (email: string, password: string, returnUrl?: string) => {
    // Collect device fingerprint for device recognition
    let deviceFingerprint: string | undefined;
    try {
      const { getDeviceFingerprint } = await import('../services/fingerprintService');
      deviceFingerprint = await getDeviceFingerprint();
    } catch (err) {
      console.warn('Failed to collect device fingerprint:', err);
    }

    const response = await authService.login({
      email,
      password,
      deviceFingerprint,
      returnUrl,
    });

    if ('status' in response && response.status === 'mfa_required') {
      return {
        mfaRequired: true,
        mfaToken: response.mfaToken,
        availableMethods: response.availableMethods,
        preferredMethod: response.preferredMethod,
        returnUrl: response.returnUrl,
      };
    }

    // Fetch user after successful login
    const currentUser = await authService.getCurrentUser();
    setUser(currentUser);

    return { mfaRequired: false, returnUrl: (response as LoginResponse).returnUrl };
  };

  const register = async (email: string, password: string): Promise<RegisterResponse> => {
    const response = await authService.register({ email, password });
    // Only auto-login if email verification is not required
    if (!response.emailVerificationRequired) {
      const currentUser = await authService.getCurrentUser();
      setUser(currentUser);
    }
    return response;
  };

  const logout = async () => {
    await authService.logout();
    setUser(null);
  };

  const refreshUser = async () => {
    try {
      const currentUser = await authService.getCurrentUser();
      setUser(currentUser);
    } catch {
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated,
        login,
        register,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
