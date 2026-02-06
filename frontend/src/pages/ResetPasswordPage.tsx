import { useState, useEffect } from 'react';
import { Link, useSearchParams, useNavigate } from 'react-router-dom';
import { authService } from '../services/authService';
import { Button, Input, Alert } from '../components/common';

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const token = searchParams.get('token');

  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isValidToken, setIsValidToken] = useState<boolean | null>(null);

  useEffect(() => {
    if (!token) {
      setIsValidToken(false);
    } else {
      // In a real app, you might verify the token first
      setIsValidToken(true);
    }
  }, [token]);

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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    const passwordError = validatePassword(password);
    if (passwordError) {
      setError(passwordError);
      return;
    }

    setIsLoading(true);

    try {
      await authService.resetPassword(token!, password);
      setSuccess(true);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to reset password. The link may have expired.';
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

  if (isValidToken === false) {
    return (
      <div className="text-center">
        <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 mb-4">
          <svg
            className="h-6 w-6 text-red-600"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M6 18L18 6M6 6l12 12"
            />
          </svg>
        </div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Invalid reset link</h2>
        <p className="text-gray-600 mb-6">
          This password reset link is invalid or has expired. Please request a new one.
        </p>
        <Link to="/forgot-password">
          <Button className="w-full">Request new link</Button>
        </Link>
      </div>
    );
  }

  if (success) {
    return (
      <div className="text-center">
        <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100 mb-4">
          <svg
            className="h-6 w-6 text-green-600"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M5 13l4 4L19 7"
            />
          </svg>
        </div>
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Password reset successful</h2>
        <p className="text-gray-600 mb-6">
          Your password has been reset successfully. You can now sign in with your new password.
        </p>
        <Button className="w-full" onClick={() => navigate('/login')}>
          Sign in
        </Button>
      </div>
    );
  }

  const passwordStrength = getPasswordStrength(password);

  return (
    <div>
      <h2 className="text-2xl font-bold text-gray-900 text-center mb-2">
        Set new password
      </h2>
      <p className="text-gray-600 text-center mb-6">
        Enter your new password below.
      </p>

      {error && (
        <Alert type="error" className="mb-4" onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <Input
            id="password"
            label="New password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="new-password"
            placeholder="••••••••"
            hint="Must be at least 12 characters with uppercase, lowercase, number, and special character"
          />
          {password && (
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
          id="confirm-password"
          label="Confirm new password"
          type="password"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
          required
          autoComplete="new-password"
          placeholder="••••••••"
          error={confirmPassword && password !== confirmPassword ? 'Passwords do not match' : undefined}
        />

        <Button type="submit" className="w-full" loading={isLoading}>
          Reset password
        </Button>
      </form>

      <div className="mt-6 text-center">
        <Link to="/login" className="text-sm font-medium text-blue-600 hover:text-blue-500">
          Back to sign in
        </Link>
      </div>
    </div>
  );
}

export default ResetPasswordPage;
