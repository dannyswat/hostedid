import { useState } from 'react';
import { Link, useNavigate, useLocation, useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Button, Input, Alert } from '../components/common';

export function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  const returnUrl = searchParams.get('return_url') || undefined;
  const from = (location.state as { from?: { pathname: string } })?.from?.pathname || '/dashboard';

  const handleRedirect = (serverReturnUrl?: string) => {
    const target = serverReturnUrl || returnUrl;
    if (target) {
      // External redirect for cross-origin/subdomain return URLs
      window.location.href = target;
    } else {
      navigate(from, { replace: true });
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const result = await login(email, password, returnUrl);
      if (result.mfaRequired && result.mfaToken) {
        // Redirect to MFA verification page
        navigate('/mfa-verify', {
          state: {
            mfaToken: result.mfaToken,
            availableMethods: result.availableMethods || [],
            preferredMethod: result.preferredMethod,
            from,
            returnUrl: result.returnUrl || returnUrl,
          },
          replace: true,
        });
      } else {
        handleRedirect(result.returnUrl);
      }
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Invalid email or password';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div>
      <h2 className="text-2xl font-bold text-gray-900 text-center mb-6">
        Sign in to your account
      </h2>

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

        <Input
          id="password"
          label="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          autoComplete="current-password"
          placeholder="••••••••"
        />

        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <input
              id="remember-me"
              name="remember-me"
              type="checkbox"
              className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
            />
            <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-700">
              Remember me
            </label>
          </div>

          <Link
            to="/forgot-password"
            className="text-sm font-medium text-blue-600 hover:text-blue-500"
          >
            Forgot password?
          </Link>
        </div>

        <Button type="submit" className="w-full" loading={isLoading}>
          Sign in
        </Button>
      </form>

      <div className="mt-6">
        <div className="relative">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300" />
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-2 bg-white text-gray-500">New to HostedID?</span>
          </div>
        </div>

        <div className="mt-6">
          <Link to={returnUrl ? `/register?return_url=${encodeURIComponent(returnUrl)}` : '/register'}>
            <Button variant="secondary" className="w-full">
              Create an account
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;
