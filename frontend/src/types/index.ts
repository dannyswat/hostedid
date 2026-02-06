// User types
export interface User {
  id: string;
  email: string;
  emailVerified: boolean;
  status: 'pending_verification' | 'active' | 'locked' | 'disabled';
  createdAt: string;
  profile?: UserProfile;
  mfaEnabled?: boolean;
}

export interface UserProfile {
  displayName?: string;
  avatarUrl?: string;
  locale: string;
  timezone: string;
  metadata?: Record<string, unknown>;
}

// Auth types
export interface LoginRequest {
  email: string;
  password: string;
  deviceFingerprint?: string;
  rememberDevice?: boolean;
  returnUrl?: string;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  idToken: string;
  tokenType: string;
  expiresIn: number;
  deviceId: string;
  returnUrl?: string;
}

export interface MFARequiredResponse {
  status: 'mfa_required';
  mfaToken: string;
  availableMethods: MFAMethod[];
  preferredMethod?: MFAMethod;
  returnUrl?: string;
}

export type MFAMethod = 'totp' | 'webauthn' | 'backup_code' | 'email_otp';

export interface RegisterRequest {
  email: string;
  password: string;
  profile?: {
    displayName?: string;
    locale?: string;
    timezone?: string;
  };
}

export interface RegisterResponse {
  userId: string;
  email: string;
  status: string;
  verificationSentAt: string;
}

// Token types
export interface RefreshTokenRequest {
  refreshToken: string;
}

export interface RefreshTokenResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

// Password types
export interface PasswordResetRequest {
  email: string;
}

export interface PasswordResetComplete {
  token: string;
  newPassword: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
  invalidateOtherSessions?: boolean;
}

// Device types
export interface Device {
  id: string;
  deviceId: string;
  deviceName: string;
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown';
  name: string;
  fingerprintHash: string;
  firstSeen: string;
  lastActivity: string;
  lastActiveAt: string;
  currentIp: string;
  ipAddress: string;
  currentLocation?: string;
  location?: string;
  browser?: string;
  os?: string;
  isTrusted: boolean;
  trustExpiresAt?: string;
  session: DeviceSession;
  isCurrentDevice: boolean;
  isCurrent: boolean;
}

export interface DeviceSession {
  isActive: boolean;
  startedAt?: string;
  expiresAt?: string;
  lastRefresh?: string;
}

// Session types
export interface SessionInfo {
  deviceId: string;
  deviceName: string;
  deviceType: 'desktop' | 'mobile' | 'tablet' | 'unknown';
  browser: string;
  os: string;
  ipAddress: string;
  location?: string;
  isActive: boolean;
  isCurrent: boolean;
  isTrusted: boolean;
  startedAt?: string;
  expiresAt?: string;
  lastActivity: string;
  firstSeen: string;
  createdAt: string;
}

export interface SessionSummary {
  totalDevices: number;
  activeSessions: number;
  trustedDevices: number;
  sessions: SessionInfo[];
}

export interface BackChannelLogoutRequest {
  deviceId?: string;
  reason?: string;
}

export interface BackChannelLogoutResponse {
  logoutToken: string;
  devicesLoggedOut: number;
  status: string;
}

// MFA types
export interface TOTPSetupResponse {
  secret: string;
  qrCode: string; // base64-encoded PNG
  issuer: string;
  accountId: string;
}

export interface MFAMethodInfo {
  method: MFAMethod;
  isPrimary: boolean;
  lastUsed?: string;
  createdAt: string;
  credentials?: WebAuthnCredentialInfo[];
}

export interface WebAuthnCredentialInfo {
  id: string;
  name: string;
  createdAt: string;
}

export interface MFAStatusResponse {
  mfaEnabled: boolean;
  preferredMethod?: MFAMethod;
  enrolledMethods: MFAMethodInfo[];
  backupCodesRemaining: number;
}

export interface BackupCodesResponse {
  codes: string[];
  count: number;
}

export interface MFAVerifyRequest {
  mfaToken: string;
  method: MFAMethod;
  code?: string;
}

export interface WebAuthnBeginResponse {
  sessionKey: string;
  options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions;
}

export interface WebAuthnRegisterCompleteRequest {
  sessionKey: string;
  credentialName?: string;
  credential: unknown;
}

export interface WebAuthnAuthenticateCompleteRequest {
  mfaToken: string;
  sessionKey: string;
  credential: unknown;
}

// API Response types
export interface ApiError {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    requestId: string;
  };
}

// Health types
export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  version: string;
  services: Record<string, string>;
}
