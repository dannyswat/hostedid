package hostedid

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
)

// Context keys for storing auth data in Echo context.
const (
	// UserContextKey is the key used to store the authenticated User in echo.Context.
	UserContextKey = "hostedid_user"

	// TokenContextKey is the key used to store the raw access token in echo.Context.
	TokenContextKey = "hostedid_token"
)

// MiddlewareConfig configures the Echo authentication middleware.
type MiddlewareConfig struct {
	// Skipper defines a function to skip this middleware for certain requests.
	// Return true to skip authentication for the request.
	Skipper func(c echo.Context) bool

	// LoginURL is the HostedID login page URL. When set, unauthenticated
	// requests are redirected here instead of returning 401.
	// The current request URL is appended as a ?return_url= query parameter.
	// Example: "https://auth.example.com/login"
	LoginURL string

	// TokenExtractor is an optional custom function to extract the access token
	// from a request. If nil, the default extractor reads from the Authorization
	// header first, then falls back to the configured cookie.
	TokenExtractor func(c echo.Context) string

	// ErrorHandler is an optional custom error handler for authentication failures.
	// If nil, the default handler returns JSON 401 errors or redirects to LoginURL.
	ErrorHandler func(c echo.Context, err error) error

	// SkipPaths is a list of path prefixes that do not require authentication.
	// Example: []string{"/health", "/public/"}
	SkipPaths []string

	// RequireVerifiedEmail rejects users whose email is not verified (HTTP 403).
	// Default: false
	RequireVerifiedEmail bool
}

// EchoAuth returns Echo middleware that authenticates requests using HostedID.
//
// The middleware extracts the access token from the Authorization header or the
// hostedid_access_token cookie, validates it against the HostedID server, and
// stores the authenticated user in the Echo context.
//
// Retrieve the user in handlers with GetUser(c).
func (client *Client) EchoAuth(cfgs ...MiddlewareConfig) echo.MiddlewareFunc {
	cfg := MiddlewareConfig{}
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Check skipper
			if cfg.Skipper != nil && cfg.Skipper(c) {
				return next(c)
			}

			// Check skip paths
			path := c.Request().URL.Path
			for _, p := range cfg.SkipPaths {
				if strings.HasPrefix(path, p) {
					return next(c)
				}
			}

			// Extract token
			token := ""
			if cfg.TokenExtractor != nil {
				token = cfg.TokenExtractor(c)
			} else {
				token = defaultTokenExtractor(c, client.cfg.CookieName)
			}

			if token == "" {
				return handleAuthError(c, cfg, ErrNoToken)
			}

			// Validate token
			user, err := client.ValidateToken(c.Request().Context(), token)
			if err != nil {
				return handleAuthError(c, cfg, err)
			}

			// Optionally require verified email
			if cfg.RequireVerifiedEmail && !user.EmailVerified {
				return c.JSON(http.StatusForbidden, map[string]interface{}{
					"error": map[string]string{
						"code":    "email_not_verified",
						"message": "Email verification required",
					},
				})
			}

			// Store user and token in context
			c.Set(UserContextKey, user)
			c.Set(TokenContextKey, token)

			return next(c)
		}
	}
}

// GetUser retrieves the authenticated HostedID user from the Echo context.
// Returns nil if the user is not authenticated (middleware not applied or skipped).
func GetUser(c echo.Context) *User {
	if user, ok := c.Get(UserContextKey).(*User); ok {
		return user
	}
	return nil
}

// GetToken retrieves the raw access token from the Echo context.
// Returns an empty string if not available.
func GetToken(c echo.Context) string {
	if token, ok := c.Get(TokenContextKey).(string); ok {
		return token
	}
	return ""
}

// RequireUser is an Echo handler helper that returns 401 if user is nil.
// Use in individual route handlers for extra safety.
//
//	e.GET("/secure", func(c echo.Context) error {
//	    user, err := hostedid.RequireUser(c)
//	    if err != nil {
//	        return err
//	    }
//	    return c.JSON(200, user)
//	})
func RequireUser(c echo.Context) (*User, error) {
	user := GetUser(c)
	if user == nil {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}
	return user, nil
}

// RedirectToLogin redirects the user to the HostedID login page with return_url
// set to the current request URL. Call this from handlers where you want to
// trigger the login flow instead of returning an error.
func RedirectToLogin(c echo.Context, loginURL string) error {
	returnURL := currentURL(c)
	target := loginURL + "?return_url=" + url.QueryEscape(returnURL)
	return c.Redirect(http.StatusFound, target)
}

// ---------- Internal helpers ----------

func defaultTokenExtractor(c echo.Context, cookieName string) string {
	// 1. Authorization: Bearer <token>
	auth := c.Request().Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// 2. Cookie
	cookie, err := c.Cookie(cookieName)
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	return ""
}

func handleAuthError(c echo.Context, cfg MiddlewareConfig, err error) error {
	// Custom error handler
	if cfg.ErrorHandler != nil {
		return cfg.ErrorHandler(c, err)
	}

	// Redirect to login if configured
	if cfg.LoginURL != "" {
		return RedirectToLogin(c, cfg.LoginURL)
	}

	// Default: JSON 401
	code := http.StatusUnauthorized
	message := "Authentication required"

	if errors.Is(err, ErrTokenInvalid) {
		message = "Invalid or expired token"
	} else if errors.Is(err, ErrTokenForbidden) {
		code = http.StatusForbidden
		message = "Access forbidden"
	}

	return c.JSON(code, map[string]interface{}{
		"error": map[string]string{
			"code":    "unauthorized",
			"message": message,
		},
	})
}

func currentURL(c echo.Context) string {
	r := c.Request()
	scheme := "https"
	if r.TLS == nil {
		scheme = c.Scheme()
	}
	return scheme + "://" + r.Host + r.RequestURI
}
