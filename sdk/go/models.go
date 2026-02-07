package hostedid

import "time"

// User represents a HostedID user returned by the API.
type User struct {
	ID            string       `json:"id"`
	Email         string       `json:"email"`
	EmailVerified bool         `json:"emailVerified"`
	Status        string       `json:"status"`
	CreatedAt     time.Time    `json:"createdAt"`
	Profile       *UserProfile `json:"profile,omitempty"`
	MFAEnabled    bool         `json:"mfaEnabled,omitempty"`
}

// UserProfile contains extended user profile information.
type UserProfile struct {
	UserID      string                 `json:"userId,omitempty"`
	DisplayName *string                `json:"displayName,omitempty"`
	AvatarURL   *string                `json:"avatarUrl,omitempty"`
	Locale      string                 `json:"locale"`
	Timezone    string                 `json:"timezone"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// LoginRequest contains the credentials for authentication.
type LoginRequest struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	DeviceFingerprint string `json:"deviceFingerprint,omitempty"`
	RememberDevice    bool   `json:"rememberDevice,omitempty"`
	ReturnURL         string `json:"returnUrl,omitempty"`
}

// LoginResponse is returned on successful authentication.
type LoginResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	IDToken      string `json:"idToken"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int    `json:"expiresIn"`
	DeviceID     string `json:"deviceId"`
	ReturnURL    string `json:"returnUrl,omitempty"`
}

// MFARequiredResponse is returned when MFA verification is needed.
type MFARequiredResponse struct {
	Status           string   `json:"status"`
	MFAToken         string   `json:"mfaToken"`
	AvailableMethods []string `json:"availableMethods"`
	PreferredMethod  string   `json:"preferredMethod,omitempty"`
	ReturnURL        string   `json:"returnUrl,omitempty"`
}

// AuthResult wraps the login response, which is either a successful login
// or an MFA challenge.
type AuthResult struct {
	// Login is set when authentication succeeds without MFA.
	Login *LoginResponse

	// MFARequired is set when MFA verification is needed.
	MFARequired *MFARequiredResponse
}

// MFAVerifyRequest contains the MFA verification code/data.
type MFAVerifyRequest struct {
	MFAToken  string `json:"mfaToken"`
	Method    string `json:"method"`
	Code      string `json:"code,omitempty"`
	ReturnURL string `json:"returnUrl,omitempty"`
}

// RegisterRequest contains the data for creating a new account.
type RegisterRequest struct {
	Email    string           `json:"email"`
	Password string           `json:"password"`
	Profile  *RegisterProfile `json:"profile,omitempty"`
}

// RegisterProfile contains optional profile data for registration.
type RegisterProfile struct {
	DisplayName string `json:"displayName,omitempty"`
	Locale      string `json:"locale,omitempty"`
	Timezone    string `json:"timezone,omitempty"`
}

// RegisterResponse is returned after successful registration.
type RegisterResponse struct {
	UserID             string    `json:"userId"`
	Email              string    `json:"email"`
	Status             string    `json:"status"`
	VerificationSentAt time.Time `json:"verificationSentAt"`
}

// RefreshTokenResponse is returned after a successful token refresh.
type RefreshTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	IDToken      string `json:"idToken,omitempty"`
	ExpiresIn    int    `json:"expiresIn"`
}
