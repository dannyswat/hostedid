import { useState, useEffect, useCallback } from 'react';
import { sessionService } from '../services/sessionService';
import type { SessionSummary, SessionInfo } from '../types';
import { Button, Alert, Loading } from '../components/common';

export function SessionsPage() {
  const [summary, setSummary] = useState<SessionSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [actionId, setActionId] = useState<string | null>(null);

  const loadSessions = useCallback(async () => {
    try {
      setIsLoading(true);
      const data = await sessionService.getUserSessions();
      setSummary(data);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load sessions';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  const handleRevokeSession = async (deviceId: string, isCurrent: boolean) => {
    if (isCurrent) {
      const confirmed = window.confirm(
        'Revoking your current session will log you out. Continue?'
      );
      if (!confirmed) return;
    }

    setActionId(deviceId);
    setError(null);

    try {
      await sessionService.revokeDeviceSession(deviceId, 'user_initiated');
      setSuccess('Session revoked successfully');
      if (isCurrent) {
        window.location.href = '/login';
      } else {
        loadSessions();
      }
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to revoke session';
      setError(errorMessage);
    } finally {
      setActionId(null);
    }
  };

  const handleRevokeAllOthers = async () => {
    const confirmed = window.confirm(
      'This will end all sessions except your current one. Connected clients will be notified via back-channel logout. Continue?'
    );
    if (!confirmed) return;

    setError(null);

    try {
      const result = await sessionService.revokeAllOtherSessions();
      setSuccess(`${result.revokedCount} session(s) revoked successfully`);
      loadSessions();
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to revoke sessions';
      setError(errorMessage);
    }
  };

  const getDeviceIcon = (deviceType: string) => {
    switch (deviceType?.toLowerCase()) {
      case 'mobile':
        return (
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
          </svg>
        );
      case 'tablet':
        return (
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M7 21h10a2 2 0 002-2V5a2 2 0 00-2-2H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
          </svg>
        );
      default:
        return (
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
        );
    }
  };

  const formatDateTime = (date: string) => {
    const d = new Date(date);
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const formatRelativeTime = (date: string) => {
    const d = new Date(date);
    const now = new Date();
    const diffMs = now.getTime() - d.getTime();
    const diffSec = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffSec < 60) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return d.toLocaleDateString();
  };

  const formatSessionDuration = (startedAt?: string) => {
    if (!startedAt) return 'N/A';
    const start = new Date(startedAt);
    const now = new Date();
    const diffMs = now.getTime() - start.getTime();
    const hours = Math.floor(diffMs / 3600000);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h`;
    return '< 1h';
  };

  const SessionCard = ({ session }: { session: SessionInfo }) => (
    <div className={`bg-white rounded-lg border ${
      session.isCurrent
        ? 'border-blue-200 ring-1 ring-blue-100'
        : session.isActive
        ? 'border-green-100'
        : 'border-gray-200'
    } p-4`}>
      <div className="flex items-start justify-between">
        <div className="flex items-start space-x-3">
          <div className={`shrink-0 w-10 h-10 rounded-lg flex items-center justify-center ${
            session.isCurrent
              ? 'bg-blue-100 text-blue-600'
              : session.isActive
              ? 'bg-green-50 text-green-600'
              : 'bg-gray-100 text-gray-400'
          }`}>
            {getDeviceIcon(session.deviceType)}
          </div>
          <div className="min-w-0">
            <div className="flex items-center space-x-2">
              <h3 className="text-sm font-medium text-gray-900 truncate">
                {session.deviceName}
              </h3>
              {session.isCurrent && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                  Current
                </span>
              )}
              {session.isTrusted && (
                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                  <svg className="w-3 h-3 mr-0.5" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                  Trusted
                </span>
              )}
            </div>
            <p className="text-sm text-gray-500 mt-0.5">
              {session.browser} &middot; {session.os}
            </p>
          </div>
        </div>
        <div className="flex items-center">
          <span className={`inline-flex items-center text-xs ${
            session.isActive ? 'text-green-600' : 'text-gray-400'
          }`}>
            <span className={`w-2 h-2 rounded-full mr-1.5 ${
              session.isActive ? 'bg-green-500' : 'bg-gray-300'
            }`} />
            {session.isActive ? 'Active' : 'Inactive'}
          </span>
        </div>
      </div>

      {/* Session Metadata */}
      <div className="mt-3 grid grid-cols-2 gap-3 text-xs text-gray-500">
        <div>
          <span className="text-gray-400 block">IP Address</span>
          <span className="font-mono">{session.ipAddress || '—'}</span>
        </div>
        <div>
          <span className="text-gray-400 block">Location</span>
          <span>{session.location || '—'}</span>
        </div>
        <div>
          <span className="text-gray-400 block">Last Activity</span>
          <span title={formatDateTime(session.lastActivity)}>
            {formatRelativeTime(session.lastActivity)}
          </span>
        </div>
        <div>
          <span className="text-gray-400 block">Session Duration</span>
          <span>{formatSessionDuration(session.startedAt)}</span>
        </div>
        {session.startedAt && (
          <div>
            <span className="text-gray-400 block">Session Started</span>
            <span>{formatDateTime(session.startedAt)}</span>
          </div>
        )}
        {session.expiresAt && (
          <div>
            <span className="text-gray-400 block">Expires</span>
            <span>{formatDateTime(session.expiresAt)}</span>
          </div>
        )}
        <div>
          <span className="text-gray-400 block">First Seen</span>
          <span>{formatDateTime(session.firstSeen)}</span>
        </div>
      </div>

      {/* Actions */}
      {session.isActive && (
        <div className="mt-3 pt-3 border-t border-gray-100 flex justify-end">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleRevokeSession(session.deviceId, session.isCurrent)}
            loading={actionId === session.deviceId}
            className="text-red-600 hover:text-red-800 hover:bg-red-50"
          >
            Revoke Session
          </Button>
        </div>
      )}
    </div>
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loading size="lg" />
      </div>
    );
  }

  const activeSessions = summary?.sessions.filter(s => s.isActive) || [];
  const inactiveSessions = summary?.sessions.filter(s => !s.isActive) || [];

  return (
    <div>
      {/* Header */}
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Active Sessions</h1>
          <p className="mt-1 text-gray-600">Monitor and manage your active sessions across devices</p>
        </div>
        {activeSessions.length > 1 && (
          <Button variant="danger" onClick={handleRevokeAllOthers}>
            Revoke all other sessions
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

      {/* Summary Stats */}
      {summary && (
        <div className="grid grid-cols-3 gap-4 mb-6">
          <div className="bg-white rounded-lg shadow px-4 py-3">
            <div className="text-2xl font-bold text-gray-900">{summary.totalDevices}</div>
            <div className="text-sm text-gray-500">Total Devices</div>
          </div>
          <div className="bg-white rounded-lg shadow px-4 py-3">
            <div className="text-2xl font-bold text-green-600">{summary.activeSessions}</div>
            <div className="text-sm text-gray-500">Active Sessions</div>
          </div>
          <div className="bg-white rounded-lg shadow px-4 py-3">
            <div className="text-2xl font-bold text-blue-600">{summary.trustedDevices}</div>
            <div className="text-sm text-gray-500">Trusted Devices</div>
          </div>
        </div>
      )}

      {/* Active Sessions */}
      {activeSessions.length > 0 && (
        <div className="mb-6">
          <h2 className="text-lg font-medium text-gray-900 mb-3">
            Active Sessions ({activeSessions.length})
          </h2>
          <div className="space-y-3">
            {activeSessions.map((session) => (
              <SessionCard key={session.deviceId} session={session} />
            ))}
          </div>
        </div>
      )}

      {/* Inactive Sessions */}
      {inactiveSessions.length > 0 && (
        <div className="mb-6">
          <h2 className="text-lg font-medium text-gray-700 mb-3">
            Recent Devices ({inactiveSessions.length})
          </h2>
          <div className="space-y-3">
            {inactiveSessions.map((session) => (
              <SessionCard key={session.deviceId} session={session} />
            ))}
          </div>
        </div>
      )}

      {activeSessions.length === 0 && inactiveSessions.length === 0 && (
        <div className="bg-white rounded-lg shadow p-8 text-center text-gray-500">
          No sessions found
        </div>
      )}

      {/* Info Section */}
      <div className="mt-6 bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-medium text-gray-900 mb-3">About Sessions</h2>
        <div className="space-y-3 text-sm text-gray-600">
          <p>
            <strong>Session tracking:</strong> Each active session represents an authenticated connection from a device. 
            Sessions include metadata such as IP address, browser, and last activity timestamp.
          </p>
          <p>
            <strong>Per-device revocation:</strong> You can revoke individual sessions to immediately sign out a specific device. 
            The device will need to re-authenticate to access your account.
          </p>
          <p>
            <strong>Back-channel logout:</strong> When you revoke sessions, connected applications are notified in real-time 
            via OIDC back-channel logout, ensuring your sessions are terminated everywhere.
          </p>
        </div>
      </div>
    </div>
  );
}

export default SessionsPage;
