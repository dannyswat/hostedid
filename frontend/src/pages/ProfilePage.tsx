import { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Button, Input, Alert } from '../components/common';

export function ProfilePage() {
  const { user } = useAuth();
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setIsLoading(true);

    try {
      // TODO: Implement profile update API call
      await new Promise((resolve) => setTimeout(resolve, 1000));
      setSuccess('Profile updated successfully');
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to update profile';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Profile</h1>
        <p className="mt-1 text-gray-600">Manage your personal information</p>
      </div>

      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-medium text-gray-900">Personal Information</h2>
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

          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="flex items-center space-x-6">
              <div className="flex-shrink-0">
                <div className="w-20 h-20 rounded-full bg-gray-300 flex items-center justify-center">
                  <span className="text-2xl font-medium text-gray-700">
                    {user?.email?.charAt(0).toUpperCase() || 'U'}
                  </span>
                </div>
              </div>
              <div>
                <Button type="button" variant="secondary" size="sm">
                  Change avatar
                </Button>
                <p className="mt-1 text-xs text-gray-500">JPG, GIF or PNG. Max size 2MB</p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Input
                id="first-name"
                label="First name"
                type="text"
                value={firstName}
                onChange={(e) => setFirstName(e.target.value)}
                placeholder="John"
              />

              <Input
                id="last-name"
                label="Last name"
                type="text"
                value={lastName}
                onChange={(e) => setLastName(e.target.value)}
                placeholder="Doe"
              />
            </div>

            <Input
              id="display-name"
              label="Display name"
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="johndoe"
              hint="This is how your name will appear to others"
            />

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Email address
              </label>
              <div className="flex items-center">
                <div className="flex-1 px-3 py-2 bg-gray-50 border border-gray-300 rounded-lg text-gray-500">
                  {user?.email || 'Not set'}
                </div>
                <Button type="button" variant="ghost" size="sm" className="ml-3">
                  Change
                </Button>
              </div>
              <p className="mt-1 text-xs text-gray-500">
                {user?.emailVerified ? (
                  <span className="text-green-600">✓ Email verified</span>
                ) : (
                  <span className="text-yellow-600">Email not verified</span>
                )}
              </p>
            </div>

            <div className="flex justify-end pt-4 border-t">
              <Button type="submit" loading={isLoading}>
                Save changes
              </Button>
            </div>
          </form>
        </div>
      </div>

      {/* Account Section */}
      <div className="mt-8 bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-medium text-gray-900">Account</h2>
        </div>

        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-medium text-gray-900">Account ID</h3>
              <p className="text-sm text-gray-500 font-mono">{user?.id || 'Not available'}</p>
            </div>
          </div>

          <div className="flex items-center justify-between pt-4 border-t">
            <div>
              <h3 className="text-sm font-medium text-gray-900">Account created</h3>
              <p className="text-sm text-gray-500">
                {user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'Not available'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Danger Zone */}
      <div className="mt-8 bg-white rounded-lg shadow border border-red-200">
        <div className="px-6 py-4 border-b border-red-200 bg-red-50">
          <h2 className="text-lg font-medium text-red-900">Danger Zone</h2>
        </div>

        <div className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-medium text-gray-900">Delete account</h3>
              <p className="text-sm text-gray-500">
                Permanently delete your account and all associated data
              </p>
            </div>
            <Button variant="danger" size="sm">
              Delete account
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ProfilePage;
