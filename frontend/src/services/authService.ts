import api, { tokenStorage } from './api';
import type {
  LoginRequest,
  LoginResponse,
  MFARequiredResponse,
  RegisterRequest,
  RegisterResponse,
  RefreshTokenResponse,
  PasswordResetComplete,
  User,
  Device,
  VerifyEmailRequest,
  VerifyEmailResponse,
  ResendVerificationRequest,
} from '../types';

export const authService = {
  /**
   * Register a new user
   */
  async register(data: RegisterRequest): Promise<RegisterResponse> {
    const response = await api.post<RegisterResponse>('/auth/register', data);
    return response.data;
  },

  /**
   * Login with email and password
   */
  async login(data: LoginRequest): Promise<LoginResponse | MFARequiredResponse> {
    const response = await api.post<LoginResponse | MFARequiredResponse>('/auth/login', data);
    
    if ('accessToken' in response.data) {
      tokenStorage.setAccessToken(response.data.accessToken);
      tokenStorage.setRefreshToken(response.data.refreshToken);
    }
    
    return response.data;
  },

  /**
   * Verify MFA code
   */
  async verifyMFA(mfaToken: string, code: string, method: string): Promise<LoginResponse> {
    const response = await api.post<LoginResponse>('/mfa/verify', {
      mfaToken,
      code,
      method,
    });
    
    tokenStorage.setAccessToken(response.data.accessToken);
    tokenStorage.setRefreshToken(response.data.refreshToken);
    
    return response.data;
  },

  /**
   * Logout current session
   */
  async logout(): Promise<void> {
    try {
      await api.post('/auth/logout');
    } finally {
      tokenStorage.clearTokens();
    }
  },

  /**
   * Logout all sessions
   */
  async logoutAll(): Promise<void> {
    try {
      await api.post('/auth/logout/all');
    } finally {
      tokenStorage.clearTokens();
    }
  },

  /**
   * Refresh access token
   */
  async refreshToken(): Promise<RefreshTokenResponse> {
    const refreshToken = tokenStorage.getRefreshToken();
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await api.post<RefreshTokenResponse>('/auth/token/refresh', {
      refreshToken,
    });

    tokenStorage.setAccessToken(response.data.accessToken);
    tokenStorage.setRefreshToken(response.data.refreshToken);

    return response.data;
  },

  /**
   * Request password reset
   */
  async requestPasswordReset(email: string): Promise<void> {
    await api.post('/auth/password/reset-request', { email });
  },

  /**
   * Complete password reset with token
   */
  async resetPassword(token: string, newPassword: string): Promise<void> {
    await api.post('/auth/password/reset-complete', { token, newPassword });
  },

  /**
   * Complete password reset (alias for backwards compatibility)
   */
  async completePasswordReset(data: PasswordResetComplete): Promise<void> {
    await api.post('/auth/password/reset-complete', data);
  },

  /**
   * Change password (authenticated)
   */
  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await api.post('/auth/password/change', { currentPassword, newPassword });
  },

  /**
   * Get current user
   */
  async getCurrentUser(): Promise<User> {
    const response = await api.get<User>('/users/me');
    return response.data;
  },

  /**
   * Verify email with OTP code
   */
  async verifyEmailOTP(data: VerifyEmailRequest): Promise<VerifyEmailResponse> {
    const response = await api.post<VerifyEmailResponse>('/auth/email/verify', data);
    return response.data;
  },

  /**
   * Resend verification OTP
   */
  async resendVerificationOTP(data: ResendVerificationRequest): Promise<void> {
    await api.post('/auth/email/resend', data);
  },

  /**
   * Verify email with token (legacy)
   */
  async verifyEmail(token: string): Promise<void> {
    await api.post('/users/me/email/verify', { token });
  },

  /**
   * Get user's devices
   */
  async getDevices(): Promise<Device[]> {
    const response = await api.get<Device[]>('/users/me/devices');
    return response.data;
  },

  /**
   * Revoke a specific device
   */
  async revokeDevice(deviceId: string): Promise<void> {
    await api.delete(`/users/me/devices/${deviceId}`);
  },

  /**
   * Revoke all devices except current
   */
  async revokeAllDevices(): Promise<void> {
    await api.post('/users/me/devices/revoke-all');
  },

  /**
   * Check if user is authenticated
   */
  isAuthenticated(): boolean {
    return !!tokenStorage.getAccessToken();
  },
};

export default authService;
