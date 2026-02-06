import { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { authService } from '../services/authService';
import { mfaService } from '../services/mfaService';
import { Button, Input, Alert } from '../components/common';
import type { MFAStatusResponse, TOTPSetupResponse, BackupCodesResponse } from '../types';

export function SecurityPage() {
  const { refreshUser } = useAuth();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const validatePassword = (password: string): string | null => {
    if (password.length < 12) {
      return 'Password must be at least 12 characters long';
    }
    if (!/[A-Z]/.test(password)) {
      return 'Password must contain at least one uppercase letter';
    }
    if (!/[a-z]/.test(password)) {
      return 'Password must contain at least one lowercase letter';
    }
    if (!/[0-9]/.test(password)) {
      return 'Password must contain at least one number';
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      return 'Password must contain at least one special character';
    }
    return null;
  };

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (newPassword !== confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    const passwordError = validatePassword(newPassword);
    if (passwordError) {
      setError(passwordError);
      return;
    }

    setIsLoading(true);

    try {
      await authService.changePassword(currentPassword, newPassword);
      setSuccess('Password changed successfully');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to change password';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const getPasswordStrength = (password: string): { strength: string; color: string } => {
    let score = 0;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score++;

    if (score <= 2) return { strength: 'Weak', color: 'bg-red-500' };
    if (score <= 4) return { strength: 'Medium', color: 'bg-yellow-500' };
    return { strength: 'Strong', color: 'bg-green-500' };
  };

  const passwordStrength = getPasswordStrength(newPassword);

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Security</h1>
        <p className="mt-1 text-gray-600">Manage your security settings and preferences</p>
      </div>

      {/* Password Section */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-medium text-gray-900">Change Password</h2>
        </div>

        <div className="p-6">
          {error && (
            <Alert type="error" className="mb-4" onClose={() => setError(null)}>
              {error}
            </Alert>
          )}

          {success && (
            <Alert type="success" className="mb-4" onClose={() => setSuccess(null)}>
              {success}
            </Alert>
          )}

          <form onSubmit={handlePasswordChange} className="space-y-4 max-w-md">
            <Input
              id="current-password"
              label="Current password"
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
              autoComplete="current-password"
              placeholder="••••••••"
            />

            <div>
              <Input
                id="new-password"
                label="New password"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                autoComplete="new-password"
                placeholder="••••••••"
                hint="Must be at least 12 characters with uppercase, lowercase, number, and special character"
              />
              {newPassword && (
                <div className="mt-2">
                  <div className="flex items-center space-x-2">
                    <div className="flex-1 h-2 bg-gray-200 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${passwordStrength.color} transition-all duration-300`}
                        style={{
                          width: passwordStrength.strength === 'Weak' ? '33%' : 
                                 passwordStrength.strength === 'Medium' ? '66%' : '100%'
                        }}
                      />
                    </div>
                    <span className="text-xs text-gray-500">{passwordStrength.strength}</span>
                  </div>
                </div>
              )}
            </div>

            <Input
              id="confirm-new-password"
              label="Confirm new password"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              autoComplete="new-password"
              placeholder="••••••••"
              error={confirmPassword && newPassword !== confirmPassword ? 'Passwords do not match' : undefined}
            />

            <div className="pt-4">
              <Button type="submit" loading={isLoading}>
                Update password
              </Button>
            </div>
          </form>
        </div>
      </div>

      {/* Two-Factor Authentication Section */}
      <MFASection refreshUser={refreshUser} />

      {/* Security Events Section */}
      <div className="mt-8 bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-medium text-gray-900">Security Events</h2>
        </div>

        <div className="p-6">
          <ul className="space-y-4">
            <li className="flex items-start">
              <div className="shrink-0">
                <div className="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center">
                  <svg
                    className="w-4 h-4 text-green-600"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"
                    />
                  </svg>
                </div>
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-900">Signed in</p>
                <p className="text-sm text-gray-500">This device • Just now</p>
              </div>
            </li>
          </ul>

          <div className="mt-4 pt-4 border-t">
            <Button variant="ghost" size="sm">
              View all security events
            </Button>
          </div>
        </div>
      </div>

      {/* Active Sessions Section */}
      <div className="mt-8 bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200 flex items-center justify-between">
          <h2 className="text-lg font-medium text-gray-900">Active Sessions</h2>
          <Button variant="danger" size="sm">
            Sign out all devices
          </Button>
        </div>

        <div className="p-6">
          <p className="text-sm text-gray-500">
            Manage your active sessions across different devices. Go to the{' '}
            <a href="/devices" className="text-blue-600 hover:text-blue-500">
              Devices page
            </a>{' '}
            to see more details.
          </p>
        </div>
      </div>
    </div>
  );
}

export default SecurityPage;

// --- MFA Management Section ---

function MFASection({ refreshUser }: { refreshUser: () => Promise<void> }) {
  const [mfaStatus, setMfaStatus] = useState<MFAStatusResponse | null>(null);
  const [totpSetup, setTotpSetup] = useState<TOTPSetupResponse | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<BackupCodesResponse | null>(null);
  const [mfaError, setMfaError] = useState<string | null>(null);
  const [mfaSuccess, setMfaSuccess] = useState<string | null>(null);
  const [mfaLoading, setMfaLoading] = useState(false);
  const [showTotpSetup, setShowTotpSetup] = useState(false);
  const [showBackupCodes, setShowBackupCodes] = useState(false);

  const loadMFAStatus = useCallback(async () => {
    try {
      const status = await mfaService.getMFAStatus();
      setMfaStatus(status);
    } catch {
      // MFA status may fail if not set up yet — that's fine
      setMfaStatus({ mfaEnabled: false, enrolledMethods: [], backupCodesRemaining: 0 });
    }
  }, []);

  useEffect(() => {
    loadMFAStatus();
  }, [loadMFAStatus]);

  const hasTOTP = mfaStatus?.enrolledMethods.some((m) => m.method === 'totp');
  const hasWebAuthn = mfaStatus?.enrolledMethods.some((m) => m.method === 'webauthn');

  // --- TOTP Setup ---
  const handleTOTPSetup = async () => {
    setMfaError(null);
    setMfaSuccess(null);
    setMfaLoading(true);
    try {
      const setup = await mfaService.setupTOTP();
      setTotpSetup(setup);
      setShowTotpSetup(true);
    } catch (err: unknown) {
      setMfaError(err instanceof Error ? err.message : 'Failed to initiate TOTP setup');
    } finally {
      setMfaLoading(false);
    }
  };

  const handleTOTPVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpCode.trim()) return;
    setMfaError(null);
    setMfaLoading(true);
    try {
      await mfaService.verifyTOTPSetup(totpCode);
      setMfaSuccess('Authenticator app has been set up successfully!');
      setShowTotpSetup(false);
      setTotpSetup(null);
      setTotpCode('');
      await loadMFAStatus();
      await refreshUser();
    } catch (err: unknown) {
      setMfaError(err instanceof Error ? err.message : 'Invalid verification code');
    } finally {
      setMfaLoading(false);
    }
  };

  const handleDisableTOTP = async () => {
    if (!confirm('Are you sure you want to disable the authenticator app? This will also remove your backup codes.')) return;
    setMfaError(null);
    setMfaLoading(true);
    try {
      await mfaService.deleteMFAMethod('totp');
      setMfaSuccess('Authenticator app has been removed.');
      await loadMFAStatus();
      await refreshUser();
    } catch (err: unknown) {
      setMfaError(err instanceof Error ? err.message : 'Failed to disable TOTP');
    } finally {
      setMfaLoading(false);
    }
  };

  // --- WebAuthn ---
  const handleWebAuthnRegister = async () => {
    setMfaError(null);
    setMfaSuccess(null);
    setMfaLoading(true);
    try {
      const { sessionKey, options } = await mfaService.beginWebAuthnRegistration();

      // Call the browser's WebAuthn API
      const credential = await navigator.credentials.create({
        publicKey: options,
      });

      if (!credential) {
        setMfaError('Security key registration was cancelled.');
        return;
      }

      const credentialName = prompt('Enter a name for this security key:', 'Security Key') || 'Security Key';

      // Serialize the credential for the server
      const pubKeyCred = credential as PublicKeyCredential;
      const attestationResponse = pubKeyCred.response as AuthenticatorAttestationResponse;
      const serialized = {
        id: pubKeyCred.id,
        rawId: btoa(String.fromCharCode(...new Uint8Array(pubKeyCred.rawId))),
        type: pubKeyCred.type,
        response: {
          attestationObject: btoa(String.fromCharCode(...new Uint8Array(attestationResponse.attestationObject))),
          clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(attestationResponse.clientDataJSON))),
        },
      };

      await mfaService.completeWebAuthnRegistration(sessionKey, credentialName, serialized);
      setMfaSuccess('Security key registered successfully!');
      await loadMFAStatus();
      await refreshUser();
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'NotAllowedError') {
        setMfaError('Security key registration was cancelled or timed out.');
      } else {
        setMfaError(err instanceof Error ? err.message : 'Failed to register security key');
      }
    } finally {
      setMfaLoading(false);
    }
  };

  const handleDisableWebAuthn = async () => {
    if (!confirm('Are you sure you want to remove all security keys?')) return;
    setMfaError(null);
    setMfaLoading(true);
    try {
      await mfaService.deleteMFAMethod('webauthn');
      setMfaSuccess('Security keys have been removed.');
      await loadMFAStatus();
      await refreshUser();
    } catch (err: unknown) {
      setMfaError(err instanceof Error ? err.message : 'Failed to remove security keys');
    } finally {
      setMfaLoading(false);
    }
  };

  // --- Backup Codes ---
  const handleGenerateBackupCodes = async () => {
    if (backupCodes && !confirm('This will replace your existing backup codes. Continue?')) return;
    setMfaError(null);
    setMfaLoading(true);
    try {
      const codes = await mfaService.generateBackupCodes();
      setBackupCodes(codes);
      setShowBackupCodes(true);
      await loadMFAStatus();
    } catch (err: unknown) {
      setMfaError(err instanceof Error ? err.message : 'Failed to generate backup codes');
    } finally {
      setMfaLoading(false);
    }
  };

  return (
    <div className="mt-8 bg-white rounded-lg shadow">
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-medium text-gray-900">Two-Factor Authentication</h2>
          {mfaStatus?.mfaEnabled && (
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
              Enabled
            </span>
          )}
        </div>
      </div>

      <div className="p-6 space-y-6">
        {mfaError && (
          <Alert type="error" className="mb-2" onClose={() => setMfaError(null)}>
            {mfaError}
          </Alert>
        )}
        {mfaSuccess && (
          <Alert type="success" className="mb-2" onClose={() => setMfaSuccess(null)}>
            {mfaSuccess}
          </Alert>
        )}

        {/* Authenticator App (TOTP) */}
        <div>
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <h3 className="text-sm font-medium text-gray-900">Authenticator App</h3>
              <p className="mt-1 text-sm text-gray-500">
                Use an authenticator app like Google Authenticator or Authy to generate one-time codes.
              </p>
              {hasTOTP ? (
                <span className="inline-flex items-center mt-2 px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                  Enabled
                </span>
              ) : (
                <span className="inline-flex items-center mt-2 px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                  Not enabled
                </span>
              )}
            </div>
            {hasTOTP ? (
              <Button variant="danger" size="sm" onClick={handleDisableTOTP} loading={mfaLoading}>
                Disable
              </Button>
            ) : (
              <Button variant="secondary" size="sm" onClick={handleTOTPSetup} loading={mfaLoading}>
                Enable
              </Button>
            )}
          </div>

          {/* TOTP Setup Flow */}
          {showTotpSetup && totpSetup && (
            <div className="mt-4 p-4 bg-gray-50 rounded-lg border">
              <h4 className="text-sm font-medium text-gray-900 mb-3">Set up Authenticator App</h4>
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-gray-600 mb-2">
                    1. Scan this QR code with your authenticator app:
                  </p>
                  <div className="flex justify-center bg-white p-4 rounded-lg w-fit mx-auto">
                    <img
                      src={`data:image/png;base64,${totpSetup.qrCode}`}
                      alt="TOTP QR Code"
                      className="w-48 h-48"
                    />
                  </div>
                </div>
                <div>
                  <p className="text-sm text-gray-600 mb-1">
                    2. Or enter this secret key manually:
                  </p>
                  <code className="block text-sm bg-white px-3 py-2 rounded border font-mono select-all break-all">
                    {totpSetup.secret}
                  </code>
                </div>
                <form onSubmit={handleTOTPVerify} className="space-y-3">
                  <p className="text-sm text-gray-600">
                    3. Enter the 6-digit code from your authenticator app:
                  </p>
                  <div className="flex space-x-3">
                    <Input
                      id="totp-code"
                      value={totpCode}
                      onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      placeholder="000000"
                      className="w-32 text-center font-mono text-lg tracking-widest"
                      autoComplete="one-time-code"
                      required
                    />
                    <Button type="submit" size="sm" loading={mfaLoading} disabled={totpCode.length !== 6}>
                      Verify
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setShowTotpSetup(false);
                        setTotpSetup(null);
                        setTotpCode('');
                      }}
                    >
                      Cancel
                    </Button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>

        {/* Passkeys / Security Keys (WebAuthn) */}
        <div className="pt-6 border-t">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <h3 className="text-sm font-medium text-gray-900">Security Keys / Passkeys</h3>
              <p className="mt-1 text-sm text-gray-500">
                Use a hardware security key or biometric passkey for strong phishing-resistant authentication.
              </p>
              {hasWebAuthn ? (
                <>
                  <span className="inline-flex items-center mt-2 px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                    {mfaStatus?.enrolledMethods.find((m) => m.method === 'webauthn')?.credentials?.length ?? 0} key(s) registered
                  </span>
                  {mfaStatus?.enrolledMethods
                    .find((m) => m.method === 'webauthn')
                    ?.credentials?.map((cred) => (
                      <div key={cred.id} className="mt-2 text-xs text-gray-500">
                        {cred.name} — added {new Date(cred.createdAt).toLocaleDateString()}
                      </div>
                    ))}
                </>
              ) : (
                <span className="inline-flex items-center mt-2 px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                  Not enabled
                </span>
              )}
            </div>
            <div className="flex space-x-2">
              <Button variant="secondary" size="sm" onClick={handleWebAuthnRegister} loading={mfaLoading}>
                {hasWebAuthn ? 'Add key' : 'Enable'}
              </Button>
              {hasWebAuthn && (
                <Button variant="danger" size="sm" onClick={handleDisableWebAuthn} loading={mfaLoading}>
                  Remove all
                </Button>
              )}
            </div>
          </div>
        </div>

        {/* Backup Codes */}
        <div className="pt-6 border-t">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <h3 className="text-sm font-medium text-gray-900">Backup Codes</h3>
              <p className="mt-1 text-sm text-gray-500">
                Generate backup codes to use when you don't have access to your authenticator app or security key.
              </p>
              {mfaStatus?.mfaEnabled && mfaStatus.backupCodesRemaining > 0 ? (
                <span className="inline-flex items-center mt-2 px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                  {mfaStatus.backupCodesRemaining} codes remaining
                </span>
              ) : mfaStatus?.mfaEnabled ? (
                <span className="inline-flex items-center mt-2 px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                  No backup codes
                </span>
              ) : null}
            </div>
            <Button
              variant="secondary"
              size="sm"
              disabled={!mfaStatus?.mfaEnabled}
              onClick={handleGenerateBackupCodes}
              loading={mfaLoading}
            >
              {mfaStatus?.backupCodesRemaining ? 'Regenerate' : 'Generate codes'}
            </Button>
          </div>

          {/* Backup Codes Display */}
          {showBackupCodes && backupCodes && (
            <div className="mt-4 p-4 bg-yellow-50 rounded-lg border border-yellow-200">
              <h4 className="text-sm font-medium text-gray-900 mb-2">Your Backup Codes</h4>
              <p className="text-xs text-gray-600 mb-3">
                Save these codes in a secure location. Each code can only be used once. These codes will not be shown again.
              </p>
              <div className="grid grid-cols-2 gap-2 max-w-xs">
                {backupCodes.codes.map((code, idx) => (
                  <code
                    key={idx}
                    className="block text-sm bg-white px-3 py-1.5 rounded border font-mono text-center select-all"
                  >
                    {code}
                  </code>
                ))}
              </div>
              <div className="mt-3 flex space-x-2">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    navigator.clipboard.writeText(backupCodes.codes.join('\n'));
                    setMfaSuccess('Backup codes copied to clipboard');
                  }}
                >
                  Copy all
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setShowBackupCodes(false);
                    setBackupCodes(null);
                  }}
                >
                  Done
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
