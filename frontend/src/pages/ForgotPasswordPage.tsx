import { useState } from 'react';
import { Link } from 'react-router-dom';
import { authService } from '../services/authService';
import { Button, Input, Alert } from '../components/common';

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      await authService.requestPasswordReset(email);
      setSuccess(true);
    } catch (err: unknown) {
      // Don't reveal if email exists or not for security
      setSuccess(true);
    } finally {
      setIsLoading(false);
    }
  };

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
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Check your email</h2>
        <p className="text-gray-600 mb-6">
          If an account exists for <strong>{email}</strong>, you will receive a password reset link
          shortly.
        </p>
        <p className="text-sm text-gray-500 mb-6">
          Didn't receive an email? Check your spam folder or try again.
        </p>
        <div className="space-y-3">
          <Button
            variant="secondary"
            className="w-full"
            onClick={() => {
              setSuccess(false);
              setEmail('');
            }}
          >
            Try another email
          </Button>
          <Link to="/login">
            <Button variant="ghost" className="w-full">
              Back to sign in
            </Button>
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div>
      <h2 className="text-2xl font-bold text-gray-900 text-center mb-2">
        Reset your password
      </h2>
      <p className="text-gray-600 text-center mb-6">
        Enter your email address and we'll send you a link to reset your password.
      </p>

      {error && (
        <Alert type="error" className="mb-4" onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <Input
          id="email"
          label="Email address"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          autoComplete="email"
          placeholder="you@example.com"
        />

        <Button type="submit" className="w-full" loading={isLoading}>
          Send reset link
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

export default ForgotPasswordPage;
