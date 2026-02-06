import api from './api';
import type { SessionSummary, SessionInfo, BackChannelLogoutRequest, BackChannelLogoutResponse } from '../types';

export const sessionService = {
  /**
   * Get all sessions for the current user with summary
   */
  async getUserSessions(): Promise<SessionSummary> {
    const response = await api.get<SessionSummary>('/sessions');
    return response.data;
  },

  /**
   * Get session info for a specific device
   */
  async getDeviceSession(deviceId: string): Promise<SessionInfo> {
    const response = await api.get<SessionInfo>(`/sessions/${deviceId}`);
    return response.data;
  },

  /**
   * Revoke the session for a specific device
   */
  async revokeDeviceSession(deviceId: string, reason?: string): Promise<void> {
    await api.post(`/sessions/${deviceId}/revoke`, { reason: reason || 'user_initiated' });
  },

  /**
   * Revoke all sessions except the current one
   */
  async revokeAllOtherSessions(): Promise<{ message: string; revokedCount: number }> {
    const response = await api.post<{ message: string; revokedCount: number }>('/sessions/revoke-others');
    return response.data;
  },

  /**
   * Trigger back-channel logout (OIDC)
   */
  async backChannelLogout(req: BackChannelLogoutRequest): Promise<BackChannelLogoutResponse> {
    const response = await api.post<BackChannelLogoutResponse>('/auth/logout/backchannel', req);
    return response.data;
  },
};

export default sessionService;
