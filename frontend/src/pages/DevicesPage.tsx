import { useState, useEffect, useCallback } from 'react';
import { deviceService } from '../services/deviceService';
import type { Device } from '../types';
import { Button, Alert, Loading } from '../components/common';

export function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [actionId, setActionId] = useState<string | null>(null);
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState('');

  const loadDevices = useCallback(async () => {
    try {
      setIsLoading(true);
      const data = await deviceService.listDevices();
      setDevices(data);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load devices';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDevices();
  }, [loadDevices]);

  const handleRevokeDevice = async (deviceId: string, isCurrent: boolean) => {
    if (isCurrent) {
      const confirmed = window.confirm(
        'Are you sure you want to sign out of this device? You will be redirected to the login page.'
      );
      if (!confirmed) return;
    }

    setActionId(deviceId);
    setError(null);

    try {
      await deviceService.removeDevice(deviceId);
      setSuccess('Device signed out successfully');
      if (isCurrent) {
        window.location.href = '/login';
      } else {
        loadDevices();
      }
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to sign out device';
      setError(errorMessage);
    } finally {
      setActionId(null);
    }
  };

  const handleRevokeAllOther = async () => {
    const confirmed = window.confirm(
      'Are you sure you want to sign out of all other devices?'
    );
    if (!confirmed) return;

    setError(null);

    try {
      await deviceService.revokeAllOtherDevices();
      setSuccess('All other devices have been signed out');
      loadDevices();
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to sign out devices';
      setError(errorMessage);
    }
  };

  const handleTrustDevice = async (deviceId: string) => {
    setActionId(deviceId);
    setError(null);

    try {
      await deviceService.trustDevice({ deviceId, durationDays: 90 });
      setSuccess('Device marked as trusted for 90 days');
      loadDevices();
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to trust device';
      setError(errorMessage);
    } finally {
      setActionId(null);
    }
  };

  const handleUntrustDevice = async (deviceId: string) => {
    setActionId(deviceId);
    setError(null);

    try {
      await deviceService.untrustDevice({ deviceId });
      setSuccess('Device trust removed');
      loadDevices();
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to untrust device';
      setError(errorMessage);
    } finally {
      setActionId(null);
    }
  };

  const handleStartRename = (device: Device) => {
    setRenamingId(device.id);
    setRenameValue(device.deviceName || device.name || '');
  };

  const handleCancelRename = () => {
    setRenamingId(null);
    setRenameValue('');
  };

  const handleSaveRename = async (deviceId: string) => {
    if (!renameValue.trim()) {
      setError('Device name cannot be empty');
      return;
    }

    setActionId(deviceId);
    setError(null);

    try {
      await deviceService.updateDevice(deviceId, { name: renameValue.trim() });
      setSuccess('Device renamed successfully');
      setRenamingId(null);
      setRenameValue('');
      loadDevices();
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to rename device';
      setError(errorMessage);
    } finally {
      setActionId(null);
    }
  };

  const getDeviceIcon = (deviceType: string) => {
    switch (deviceType?.toLowerCase()) {
      case 'mobile':
        return (
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
          </svg>
        );
      case 'tablet':
        return (
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M7 21h10a2 2 0 002-2V5a2 2 0 00-2-2H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
          </svg>
        );
      default:
        return (
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
        );
    }
  };

  const formatLastActive = (date: string) => {
    const d = new Date(date);
    const now = new Date();
    const diffMs = now.getTime() - d.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 5) return 'Just now';
    if (diffMins < 60) return `${diffMins} minutes ago`;
    if (diffHours < 24) return `${diffHours} hours ago`;
    if (diffDays < 7) return `${diffDays} days ago`;
    return d.toLocaleDateString();
  };

  const formatTrustExpiry = (date: string) => {
    const d = new Date(date);
    const now = new Date();
    const diffDays = Math.ceil((d.getTime() - now.getTime()) / 86400000);
    if (diffDays <= 0) return 'Expired';
    if (diffDays === 1) return 'Expires tomorrow';
    if (diffDays < 30) return `Expires in ${diffDays} days`;
    return `Expires ${d.toLocaleDateString()}`;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loading size="lg" />
      </div>
    );
  }

  return (
    <div>
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Devices</h1>
          <p className="mt-1 text-gray-600">Manage your active sessions and trusted devices</p>
        </div>
        {devices.length > 1 && (
          <Button variant="danger" onClick={handleRevokeAllOther}>
            Sign out all other devices
          </Button>
        )}
      </div>

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

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <ul className="divide-y divide-gray-200">
          {devices.length === 0 ? (
            <li className="px-6 py-8 text-center text-gray-500">
              No devices found
            </li>
          ) : (
            devices.map((device) => (
              <li key={device.id} className="px-6 py-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center flex-1 min-w-0">
                    <div className={`shrink-0 w-12 h-12 rounded-lg flex items-center justify-center ${
                      device.isCurrent || device.isCurrentDevice
                        ? 'bg-blue-100 text-blue-600'
                        : device.isTrusted
                        ? 'bg-green-50 text-green-600'
                        : 'bg-gray-100 text-gray-600'
                    }`}>
                      {getDeviceIcon(device.deviceType)}
                    </div>
                    <div className="ml-4 flex-1 min-w-0">
                      <div className="flex items-center">
                        {renamingId === device.id ? (
                          <div className="flex items-center space-x-2">
                            <input
                              type="text"
                              value={renameValue}
                              onChange={(e) => setRenameValue(e.target.value)}
                              className="text-sm border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
                              maxLength={100}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') handleSaveRename(device.id);
                                if (e.key === 'Escape') handleCancelRename();
                              }}
                              autoFocus
                            />
                            <button
                              onClick={() => handleSaveRename(device.id)}
                              className="text-blue-600 hover:text-blue-800 text-sm font-medium"
                              disabled={actionId === device.id}
                            >
                              Save
                            </button>
                            <button
                              onClick={handleCancelRename}
                              className="text-gray-500 hover:text-gray-700 text-sm"
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <>
                            <h3 className="text-sm font-medium text-gray-900 truncate">
                              {device.deviceName || device.name || 'Unknown Device'}
                            </h3>
                            <button
                              onClick={() => handleStartRename(device)}
                              className="ml-2 text-gray-400 hover:text-gray-600"
                              title="Rename device"
                            >
                              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                              </svg>
                            </button>
                          </>
                        )}
                        {(device.isCurrent || device.isCurrentDevice) && (
                          <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                            This device
                          </span>
                        )}
                      </div>
                      <div className="mt-1 text-sm text-gray-500">
                        <span>{device.browser || 'Unknown browser'}</span>
                        <span className="mx-1">&middot;</span>
                        <span>{device.os || 'Unknown OS'}</span>
                      </div>
                      <div className="mt-1 text-xs text-gray-400">
                        <span>Last active: {formatLastActive(device.lastActiveAt || device.lastActivity)}</span>
                        {(device.ipAddress || device.currentIp) && (
                          <>
                            <span className="mx-1">&middot;</span>
                            <span>{device.ipAddress || device.currentIp}</span>
                          </>
                        )}
                        {(device.location || device.currentLocation) && (
                          <>
                            <span className="mx-1">&middot;</span>
                            <span>{device.location || device.currentLocation}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2 ml-4">
                    {device.isTrusted ? (
                      <div className="flex items-center space-x-2">
                        <div className="text-right">
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                            <svg className="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                              <path fillRule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                            </svg>
                            Trusted
                          </span>
                          {device.trustExpiresAt && (
                            <p className="text-xs text-gray-400 mt-0.5">
                              {formatTrustExpiry(device.trustExpiresAt)}
                            </p>
                          )}
                        </div>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleUntrustDevice(device.id)}
                          loading={actionId === device.id}
                        >
                          Untrust
                        </Button>
                      </div>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleTrustDevice(device.id)}
                        loading={actionId === device.id}
                      >
                        Trust
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleRevokeDevice(device.id, device.isCurrent || device.isCurrentDevice)}
                      loading={actionId === device.id}
                      className="text-red-600 hover:text-red-800"
                    >
                      Sign out
                    </Button>
                  </div>
                </div>

                {/* Session details */}
                {device.session && (
                  <div className="mt-2 ml-16 flex items-center space-x-4 text-xs text-gray-400">
                    <span className={`inline-flex items-center ${device.session.isActive ? 'text-green-500' : 'text-gray-400'}`}>
                      <span className={`w-1.5 h-1.5 rounded-full mr-1 ${device.session.isActive ? 'bg-green-500' : 'bg-gray-300'}`} />
                      {device.session.isActive ? 'Active session' : 'Inactive'}
                    </span>
                    {device.session.startedAt && (
                      <span>Session started: {new Date(device.session.startedAt).toLocaleDateString()}</span>
                    )}
                  </div>
                )}
              </li>
            ))
          )}
        </ul>
      </div>

      {/* Device Info Section */}
      <div className="mt-8 bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-medium text-gray-900 mb-4">About Devices</h2>
        <div className="space-y-4 text-sm text-gray-600">
          <p>
            <strong>What is a device?</strong> A device represents an active session where you&apos;re signed in to your account. 
            This includes web browsers, mobile apps, and other applications.
          </p>
          <p>
            <strong>Security tip:</strong> Regularly review your active devices and sign out of any you don&apos;t recognize. 
            If you see any suspicious activity, change your password immediately.
          </p>
          <p>
            <strong>Trusted devices:</strong> Mark devices you own and use regularly as trusted. 
            Trusted devices may skip additional verification steps like MFA for a configured period (default: 90 days).
            You can revoke trust at any time.
          </p>
          <p>
            <strong>Device fingerprinting:</strong> We use browser characteristics to recognize your devices. 
            This helps detect unauthorized access and provides a better security experience.
          </p>
        </div>
      </div>
    </div>
  );
}

export default DevicesPage;
