package model

import "time"

// AuditLog represents an audit log entry
type AuditLog struct {
	ID           string                 `json:"id"`
	UserID       *string                `json:"userId,omitempty"`
	Action       string                 `json:"action"`
	ResourceType *string                `json:"resourceType,omitempty"`
	ResourceID   *string                `json:"resourceId,omitempty"`
	IPAddress    *string                `json:"ipAddress,omitempty"`
	UserAgent    *string                `json:"userAgent,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt    time.Time              `json:"createdAt"`
}

// Audit action constants
const (
	AuditActionRegister             = "user.register"
	AuditActionLogin                = "user.login"
	AuditActionLoginFailed          = "user.login_failed"
	AuditActionLogout               = "user.logout"
	AuditActionPasswordChange       = "user.password_change"
	AuditActionPasswordResetRequest = "user.password_reset_request"
	AuditActionPasswordReset        = "user.password_reset"
	AuditActionTokenRefresh         = "token.refresh"
	AuditActionAccountUnlock        = "user.account_unlock"
	AuditActionKeyRotation          = "key.rotation"
	AuditActionMFATOTPSetup         = "mfa.totp_setup"
	AuditActionMFATOTPVerified      = "mfa.totp_verified"
	AuditActionMFAWebAuthnRegister  = "mfa.webauthn_registered"
	AuditActionMFAWebAuthnVerified  = "mfa.webauthn_verified"
	AuditActionMFAVerified          = "mfa.verified"
	AuditActionMFAMethodDisabled    = "mfa.method_disabled"
	AuditActionMFABackupCodesGen    = "mfa.backup_codes_generated"
	AuditActionDeviceTrusted        = "device.trusted"
	AuditActionDeviceUntrusted      = "device.untrusted"
	AuditActionDeviceRenamed        = "device.renamed"
	AuditActionDeviceRemoved        = "device.removed"
	AuditActionDeviceLogout         = "device.logout"
	AuditActionSessionRevoked       = "session.revoked"
	AuditActionSessionRevokedAll    = "session.revoked_all"
	AuditActionBackChannelLogout    = "session.backchannel_logout"
)
