import api from './api';
import type {
  TOTPSetupResponse,
  MFAStatusResponse,
  BackupCodesResponse,
  LoginResponse,
} from '../types';

export const mfaService = {
  // --- Status ---

  /**
   * Get MFA enrollment status and methods
   */
  async getMFAStatus(): Promise<MFAStatusResponse> {
    const response = await api.get<MFAStatusResponse>('/mfa/methods');
    return response.data;
  },

  // --- TOTP ---

  /**
   * Initiate TOTP setup - returns secret and QR code
   */
  async setupTOTP(): Promise<TOTPSetupResponse> {
    const response = await api.post<TOTPSetupResponse>('/mfa/totp/setup');
    return response.data;
  },

  /**
   * Verify TOTP code to complete setup
   */
  async verifyTOTPSetup(code: string): Promise<void> {
    await api.post('/mfa/totp/verify', { code });
  },

  // --- WebAuthn ---

  /**
   * Begin WebAuthn registration ceremony
   */
  async beginWebAuthnRegistration(): Promise<{ sessionKey: string; options: PublicKeyCredentialCreationOptions }> {
    const response = await api.post<{ sessionKey: string; options: PublicKeyCredentialCreationOptions }>(
      '/mfa/webauthn/register/begin'
    );
    return response.data;
  },

  /**
   * Complete WebAuthn registration ceremony
   */
  async completeWebAuthnRegistration(
    sessionKey: string,
    credentialName: string,
    credential: unknown
  ): Promise<void> {
    await api.post('/mfa/webauthn/register/complete', {
      sessionKey,
      credentialName,
      credential,
    });
  },

  /**
   * Begin WebAuthn authentication ceremony (during MFA challenge)
   */
  async beginWebAuthnAuthentication(mfaToken: string): Promise<{ sessionKey: string; options: PublicKeyCredentialRequestOptions }> {
    const response = await api.post<{ sessionKey: string; options: PublicKeyCredentialRequestOptions }>(
      '/mfa/webauthn/authenticate/begin',
      { mfaToken }
    );
    return response.data;
  },

  /**
   * Complete WebAuthn authentication ceremony (during MFA challenge)
   */
  async completeWebAuthnAuthentication(
    mfaToken: string,
    sessionKey: string,
    credential: unknown,
    returnUrl?: string
  ): Promise<LoginResponse> {
    const response = await api.post<LoginResponse>('/mfa/webauthn/authenticate/complete', {
      mfaToken,
      sessionKey,
      credential,
      returnUrl,
    });
    return response.data;
  },

  // --- MFA Verify (Login challenge) ---

  /**
   * Verify MFA code during login (TOTP or backup code)
   */
  async verifyMFA(mfaToken: string, code: string, method: string, returnUrl?: string): Promise<LoginResponse> {
    const response = await api.post<LoginResponse>('/mfa/verify', {
      mfaToken,
      code,
      method,
      returnUrl,
    });
    return response.data;
  },

  // --- Backup Codes ---

  /**
   * Generate new set of backup codes
   */
  async generateBackupCodes(): Promise<BackupCodesResponse> {
    const response = await api.post<BackupCodesResponse>('/mfa/backup-codes/generate');
    return response.data;
  },

  // --- Delete ---

  /**
   * Remove an MFA method (totp or webauthn)
   */
  async deleteMFAMethod(method: 'totp' | 'webauthn'): Promise<void> {
    await api.delete(`/mfa/${method}`);
  },
};

export default mfaService;
