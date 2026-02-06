import { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Button, Input, Alert } from '../components/common';
import { mfaService } from '../services/mfaService';
import { tokenStorage } from '../services/api';
import { useAuth } from '../contexts/AuthContext';
import type { MFAMethod } from '../types';

interface MFALocationState {
  mfaToken: string;
  availableMethods: MFAMethod[];
  preferredMethod?: MFAMethod;
  from?: string;
  returnUrl?: string;
}

export function MFAVerifyPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const { refreshUser } = useAuth();

  const state = location.state as MFALocationState | null;
  const mfaToken = state?.mfaToken || '';
  const availableMethods = state?.availableMethods || [];
  const from = state?.from || '/dashboard';
  const returnUrl = state?.returnUrl;

  const [selectedMethod, setSelectedMethod] = useState<MFAMethod>(
    state?.preferredMethod || availableMethods[0] || 'totp'
  );
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Redirect if accessed directly without MFA state
  if (!mfaToken) {
    return (
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 mb-4">Session Expired</h2>
        <p className="text-gray-600 mb-4">Your MFA session has expired. Please log in again.</p>
        <Button onClick={() => navigate('/login', { replace: true })}>
          Back to Login
        </Button>
      </div>
    );
  }

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!code.trim()) {
      setError('Please enter a verification code');
      return;
    }

    setIsLoading(true);
    try {
      const response = await mfaService.verifyMFA(mfaToken, code, selectedMethod, returnUrl);
      tokenStorage.setAccessToken(response.accessToken);
      tokenStorage.setRefreshToken(response.refreshToken);
      await refreshUser();
      const target = response.returnUrl || returnUrl;
      if (target) {
        window.location.href = target;
      } else {
        navigate(from, { replace: true });
      }
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosErr = err as { response?: { data?: { error?: { message?: string; code?: string } } } };
        const errCode = axiosErr.response?.data?.error?.code;
        if (errCode === 'mfa_session_expired' || errCode === 'invalid_mfa_token') {
          setError('Your MFA session has expired. Please log in again.');
          setTimeout(() => navigate('/login', { replace: true }), 2000);
          return;
        }
        setError(axiosErr.response?.data?.error?.message || 'Verification failed');
      } else {
        setError(err instanceof Error ? err.message : 'Verification failed');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleWebAuthn = async () => {
    setError(null);
    setIsLoading(true);
    try {
      const { sessionKey, options } = await mfaService.beginWebAuthnAuthentication(mfaToken);

      const credential = await navigator.credentials.get({
        publicKey: options,
      });

      if (!credential) {
        setError('Security key authentication was cancelled.');
        setIsLoading(false);
        return;
      }

      const pubKeyCred = credential as PublicKeyCredential;
      const assertionResponse = pubKeyCred.response as AuthenticatorAssertionResponse;
      const serialized = {
        id: pubKeyCred.id,
        rawId: btoa(String.fromCharCode(...new Uint8Array(pubKeyCred.rawId))),
        type: pubKeyCred.type,
        response: {
          authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertionResponse.authenticatorData))),
          clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertionResponse.clientDataJSON))),
          signature: btoa(String.fromCharCode(...new Uint8Array(assertionResponse.signature))),
          userHandle: assertionResponse.userHandle
            ? btoa(String.fromCharCode(...new Uint8Array(assertionResponse.userHandle)))
            : null,
        },
      };

      const response = await mfaService.completeWebAuthnAuthentication(mfaToken, sessionKey, serialized, returnUrl);
      tokenStorage.setAccessToken(response.accessToken);
      tokenStorage.setRefreshToken(response.refreshToken);
      await refreshUser();
      const target = response.returnUrl || returnUrl;
      if (target) {
        window.location.href = target;
      } else {
        navigate(from, { replace: true });
      }
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'NotAllowedError') {
        setError('Security key authentication was cancelled or timed out.');
      } else {
        setError(err instanceof Error ? err.message : 'WebAuthn authentication failed');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const methodLabels: Record<MFAMethod, string> = {
    totp: 'Authenticator App',
    webauthn: 'Security Key',
    backup_code: 'Backup Code',
    email_otp: 'Email Code',
  };

  return (
    <div>
      <h2 className="text-2xl font-bold text-gray-900 text-center mb-2">
        Two-Factor Authentication
      </h2>
      <p className="text-gray-600 text-center mb-6">
        Verify your identity to complete sign in
      </p>

      {error && (
        <Alert type="error" className="mb-4" onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Method Selector */}
      {availableMethods.length > 1 && (
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-2">
            Verification method
          </label>
          <div className="flex flex-wrap gap-2">
            {availableMethods.map((method) => (
              <button
                key={method}
                type="button"
                onClick={() => {
                  setSelectedMethod(method);
                  setCode('');
                  setError(null);
                }}
                className={`px-3 py-1.5 text-sm rounded-lg border transition-colors ${
                  selectedMethod === method
                    ? 'bg-blue-50 border-blue-300 text-blue-700'
                    : 'bg-white border-gray-300 text-gray-600 hover:bg-gray-50'
                }`}
              >
                {methodLabels[method]}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* WebAuthn Flow */}
      {selectedMethod === 'webauthn' ? (
        <div className="text-center py-6">
          <div className="mb-4">
            <svg className="w-16 h-16 mx-auto text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
            </svg>
          </div>
          <p className="text-sm text-gray-600 mb-4">
            Insert your security key and activate it when prompted.
          </p>
          <Button onClick={handleWebAuthn} loading={isLoading} className="w-full">
            Use Security Key
          </Button>
        </div>
      ) : (
        /* TOTP / Backup Code Flow */
        <form onSubmit={handleVerify} className="space-y-4">
          <Input
            id="mfa-code"
            label={selectedMethod === 'backup_code' ? 'Backup code' : 'Verification code'}
            value={code}
            onChange={(e) => {
              if (selectedMethod === 'backup_code') {
                setCode(e.target.value.replace(/[^a-zA-Z0-9]/g, '').slice(0, 8));
              } else {
                setCode(e.target.value.replace(/\D/g, '').slice(0, 6));
              }
            }}
            placeholder={selectedMethod === 'backup_code' ? 'Enter backup code' : '000000'}
            autoComplete="one-time-code"
            autoFocus
            required
            hint={
              selectedMethod === 'backup_code'
                ? 'Enter one of your 8-character backup codes'
                : 'Enter the 6-digit code from your authenticator app'
            }
          />

          <Button
            type="submit"
            className="w-full"
            loading={isLoading}
            disabled={selectedMethod === 'backup_code' ? code.length < 8 : code.length < 6}
          >
            Verify
          </Button>
        </form>
      )}

      <div className="mt-6 text-center">
        <button
          type="button"
          onClick={() => navigate('/login', { replace: true })}
          className="text-sm text-gray-500 hover:text-gray-700"
        >
          Back to login
        </button>
      </div>
    </div>
  );
}

export default MFAVerifyPage;
