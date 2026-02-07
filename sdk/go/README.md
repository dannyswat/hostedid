# HostedID Go SDK for Echo

A Go SDK for integrating [HostedID](../../README.md) authentication into applications built with the [Echo](https://echo.labstack.com/) web framework.

## Features

- **Echo Middleware** — Protect routes with a single line of code
- **Cookie-Based SSO** — Automatic token extraction from cross-subdomain cookies
- **Header-Based Auth** — Supports `Authorization: Bearer` tokens for API clients
- **Token Caching** — In-memory cache reduces calls to the HostedID server
- **Login Redirect** — Redirect unauthenticated users to the HostedID login page with `return_url`
- **Full API Client** — Login, register, logout, MFA verify, token refresh

## Installation

```bash
go get github.com/dannyswat/hostedid/hostedid-go
```

## Quick Start

### 1. Create a HostedID Client

```go
package main

import (
    "github.com/labstack/echo/v4"
    hostedid "github.com/dannyswat/hostedid/hostedid-go"
)

func main() {
    // Initialize the HostedID client
    auth := hostedid.NewClient(hostedid.Config{
        BaseURL: "https://auth.example.com", // Your HostedID server URL
    })

    e := echo.New()

    // Apply the authentication middleware globally
    e.Use(auth.EchoAuth())

    // This route is now protected
    e.GET("/profile", func(c echo.Context) error {
        user := hostedid.GetUser(c)
        return c.JSON(200, map[string]interface{}{
            "id":    user.ID,
            "email": user.Email,
        })
    })

    e.Start(":3000")
}
```

### 2. Protect Specific Route Groups

```go
func main() {
    auth := hostedid.NewClient(hostedid.Config{
        BaseURL: "https://auth.example.com",
    })

    e := echo.New()

    // Public routes (no auth)
    e.GET("/health", healthHandler)
    e.GET("/", homeHandler)

    // Protected routes
    api := e.Group("/api", auth.EchoAuth())
    api.GET("/profile", profileHandler)
    api.GET("/settings", settingsHandler)

    e.Start(":3000")
}
```

## Configuration

### Client Config

```go
auth := hostedid.NewClient(hostedid.Config{
    // Required: URL of your HostedID server.
    // The "/api/v1" suffix is appended automatically if missing.
    BaseURL: "https://auth.example.com",

    // Optional: Cookie name for the access token.
    // Default: "hostedid_access_token"
    CookieName: "hostedid_access_token",

    // Optional: How long validated tokens are cached in memory.
    // Set to 0 to disable caching (every request calls HostedID).
    // Default: 2 minutes
    CacheTTL: 2 * time.Minute,

    // Optional: Custom HTTP client for outbound requests to HostedID.
    // Default: http.Client with 10s timeout
    HTTPClient: &http.Client{Timeout: 5 * time.Second},
})
```

### Middleware Config

```go
e.Use(auth.EchoAuth(hostedid.MiddlewareConfig{
    // Skip authentication for certain paths
    SkipPaths: []string{"/health", "/public/"},

    // Redirect to HostedID login instead of returning 401
    LoginURL: "https://auth.example.com/login",

    // Require email verification
    RequireVerifiedEmail: true,

    // Custom skipper function
    Skipper: func(c echo.Context) bool {
        return c.Request().Method == "OPTIONS"
    },

    // Custom error handler
    ErrorHandler: func(c echo.Context, err error) error {
        return c.Redirect(302, "/login")
    },

    // Custom token extractor
    TokenExtractor: func(c echo.Context) string {
        // e.g., read from a custom header
        return c.Request().Header.Get("X-Auth-Token")
    },
}))
```

## How Authentication Works

### Cookie-Based SSO (Recommended for Web Apps)

When HostedID and your application share the same parent domain, authentication works automatically via cookies:

```
1. User visits your app at app.example.com
2. Echo middleware checks for the hostedid_access_token cookie
3. If present, validates the token against HostedID
4. If missing/invalid, returns 401 or redirects to HostedID login

Cookie flow:
┌──────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  auth.example.com│     │  app.example.com │     │  HostedID Server│
│  (HostedID UI)   │     │  (Your Echo App) │     │  (API Backend)  │
└────────┬─────────┘     └────────┬─────────┘     └────────┬────────┘
         │                        │                        │
         │  1. User logs in       │                        │
         │  ─────────────────────────────────────────────► │
         │                        │                        │
         │  2. Set cookies        │                        │
         │  (Domain=.example.com) │                        │
         │  ◄───────────────────────────────────────────── │
         │                        │                        │
         │                        │  3. Browser sends      │
         │                        │     cookie to app      │
         │                        │  ◄── User visits ──    │
         │                        │                        │
         │                        │  4. Middleware reads    │
         │                        │     cookie, validates   │
         │                        │  ─────────────────────►│
         │                        │                        │
         │                        │  5. User info returned │
         │                        │  ◄─────────────────────│
         │                        │                        │
```

**HostedID Cookie Configuration** (in HostedID's `config.yaml`):
```yaml
cookie:
  domain: ".example.com"     # Share cookies across all subdomains
  secure: true               # Require HTTPS
  same_site: "lax"
  allowed_return_urls:
    - "https://app.example.com"
```

### Header-Based Auth (For API Clients)

API clients (mobile apps, server-to-server) send the access token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer eyJhbG..." https://app.example.com/api/profile
```

The middleware automatically checks the `Authorization: Bearer` header before falling back to cookies.

## Login Redirect with return_url

When `LoginURL` is configured, unauthenticated users are automatically redirected to the HostedID login page. After login, they are redirected back to your app:

```go
e.Use(auth.EchoAuth(hostedid.MiddlewareConfig{
    LoginURL: "https://auth.example.com/login",
}))
```

**Flow:**
1. User visits `https://app.example.com/dashboard` (not authenticated)
2. Middleware redirects to `https://auth.example.com/login?return_url=https%3A%2F%2Fapp.example.com%2Fdashboard`
3. User logs in at HostedID
4. HostedID sets cookies and redirects back to `https://app.example.com/dashboard`
5. Middleware reads the cookie and authenticates the user

You can also trigger login redirects manually from handlers:

```go
e.GET("/login", func(c echo.Context) error {
    return hostedid.RedirectToLogin(c, "https://auth.example.com/login")
})
```

## Accessing User Data in Handlers

### GetUser

```go
e.GET("/profile", func(c echo.Context) error {
    user := hostedid.GetUser(c)
    if user == nil {
        return echo.NewHTTPError(401, "Not authenticated")
    }

    return c.JSON(200, map[string]interface{}{
        "id":            user.ID,
        "email":         user.Email,
        "emailVerified": user.EmailVerified,
        "status":        user.Status,
        "profile":       user.Profile,
    })
})
```

### RequireUser (Safe Helper)

```go
e.GET("/settings", func(c echo.Context) error {
    user, err := hostedid.RequireUser(c)
    if err != nil {
        return err // Returns 401 automatically
    }

    return c.JSON(200, user)
})
```

### GetToken

```go
e.POST("/proxy", func(c echo.Context) error {
    // Forward the token to another service
    token := hostedid.GetToken(c)

    req, _ := http.NewRequest("GET", "https://other-service.example.com/data", nil)
    req.Header.Set("Authorization", "Bearer "+token)
    // ...
})
```

## API Client Usage

The SDK also provides a full API client for server-side operations:

### Login

```go
result, err := auth.Login(ctx, hostedid.LoginRequest{
    Email:    "user@example.com",
    Password: "secure_password",
    ReturnURL: "https://app.example.com/callback",
})
if err != nil {
    // Handle API error
    if apiErr, ok := hostedid.IsAPIError(err); ok {
        fmt.Printf("Error %s: %s\n", apiErr.Code, apiErr.Message)
    }
    return err
}

if result.MFARequired != nil {
    // MFA challenge — prompt user for TOTP/WebAuthn code
    fmt.Println("MFA required, token:", result.MFARequired.MFAToken)
    fmt.Println("Methods:", result.MFARequired.AvailableMethods)
} else {
    // Login successful
    fmt.Println("Access Token:", result.Login.AccessToken)
    fmt.Println("Redirect to:", result.Login.ReturnURL)
}
```

### MFA Verification

```go
loginResp, err := auth.VerifyMFA(ctx, hostedid.MFAVerifyRequest{
    MFAToken: mfaToken,
    Method:   "totp",
    Code:     "123456",
})
if err != nil {
    return err
}
fmt.Println("Access Token:", loginResp.AccessToken)
```

### Register

```go
resp, err := auth.Register(ctx, hostedid.RegisterRequest{
    Email:    "newuser@example.com",
    Password: "Str0ng!Password#123",
    Profile: &hostedid.RegisterProfile{
        DisplayName: "New User",
        Timezone:    "America/New_York",
    },
})
if err != nil {
    return err
}
fmt.Println("User created:", resp.UserID)
```

### Logout

```go
// Logout current session
err := auth.Logout(ctx, accessToken)

// Logout all sessions
err = auth.LogoutAll(ctx, accessToken)
```

### Token Refresh

```go
resp, err := auth.RefreshToken(ctx, refreshToken)
if err != nil {
    return err
}
fmt.Println("New Access Token:", resp.AccessToken)
```

### Validate Token

```go
user, err := auth.ValidateToken(ctx, token)
if err != nil {
    if errors.Is(err, hostedid.ErrTokenInvalid) {
        // Token expired or invalid
    }
    return err
}
fmt.Println("Authenticated user:", user.Email)
```

## Error Handling

The SDK returns structured errors for API failures:

```go
result, err := auth.Login(ctx, req)
if err != nil {
    if apiErr, ok := hostedid.IsAPIError(err); ok {
        switch apiErr.Code {
        case "invalid_credentials":
            // Wrong email/password
        case "account_locked":
            // Account is locked
        case "rate_limited":
            // Too many attempts
        default:
            log.Printf("API error [%s]: %s", apiErr.Code, apiErr.Message)
        }
    }
    return err
}
```

Sentinel errors for token validation:

| Error | Description |
|-------|-------------|
| `hostedid.ErrNoToken` | No token found in request |
| `hostedid.ErrTokenInvalid` | Token is expired or invalid |
| `hostedid.ErrTokenForbidden` | Token valid but access denied |

## Complete Example

```go
package main

import (
    "net/http"
    "time"

    "github.com/labstack/echo/v4"
    "github.com/labstack/echo/v4/middleware"
    hostedid "github.com/dannyswat/hostedid/hostedid-go"
)

func main() {
    // Configure HostedID client
    auth := hostedid.NewClient(hostedid.Config{
        BaseURL:  "https://auth.example.com",
        CacheTTL: 2 * time.Minute,
    })

    e := echo.New()

    // Standard Echo middleware
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())

    // Public routes
    e.GET("/health", func(c echo.Context) error {
        return c.JSON(200, map[string]string{"status": "ok"})
    })

    // Login redirect for unauthenticated web users
    e.GET("/login", func(c echo.Context) error {
        return hostedid.RedirectToLogin(c, "https://auth.example.com/login")
    })

    // Protected routes with login redirect
    web := e.Group("", auth.EchoAuth(hostedid.MiddlewareConfig{
        LoginURL:  "https://auth.example.com/login",
        SkipPaths: []string{"/health", "/login"},
    }))

    web.GET("/", func(c echo.Context) error {
        user := hostedid.GetUser(c)
        return c.HTML(200, "<h1>Welcome, "+user.Email+"!</h1>")
    })

    web.GET("/dashboard", func(c echo.Context) error {
        user := hostedid.GetUser(c)
        return c.JSON(200, map[string]interface{}{
            "message": "Hello from the dashboard",
            "user":    user,
        })
    })

    // API routes (return 401 JSON instead of redirect)
    api := e.Group("/api", auth.EchoAuth())

    api.GET("/me", func(c echo.Context) error {
        user, err := hostedid.RequireUser(c)
        if err != nil {
            return err
        }
        return c.JSON(200, user)
    })

    api.POST("/logout", func(c echo.Context) error {
        token := hostedid.GetToken(c)
        if err := auth.Logout(c.Request().Context(), token); err != nil {
            return echo.NewHTTPError(http.StatusInternalServerError, "Logout failed")
        }
        return c.JSON(200, map[string]string{"message": "Logged out"})
    })

    e.Start(":3000")
}
```

## Data Types

### User

```go
type User struct {
    ID            string       `json:"id"`
    Email         string       `json:"email"`
    EmailVerified bool         `json:"emailVerified"`
    Status        string       `json:"status"`        // "active", "locked", etc.
    CreatedAt     time.Time    `json:"createdAt"`
    Profile       *UserProfile `json:"profile,omitempty"`
    MFAEnabled    bool         `json:"mfaEnabled,omitempty"`
}

type UserProfile struct {
    DisplayName *string                `json:"displayName,omitempty"`
    AvatarURL   *string                `json:"avatarUrl,omitempty"`
    Locale      string                 `json:"locale"`
    Timezone    string                 `json:"timezone"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
```

### AuthResult

```go
type AuthResult struct {
    Login       *LoginResponse       // Set on successful login
    MFARequired *MFARequiredResponse // Set when MFA is required
}

type LoginResponse struct {
    AccessToken  string `json:"accessToken"`
    RefreshToken string `json:"refreshToken"`
    IDToken      string `json:"idToken"`
    TokenType    string `json:"tokenType"`
    ExpiresIn    int    `json:"expiresIn"`
    DeviceID     string `json:"deviceId"`
    ReturnURL    string `json:"returnUrl,omitempty"`
}
```

## Token Caching

The SDK caches validated tokens in memory to avoid calling the HostedID server on every request. By default, tokens are cached for **2 minutes**.

- Cache is keyed by the raw token string
- Expired entries are cleaned up automatically every 5 minutes
- `Logout()` and `InvalidateToken()` remove entries from cache immediately
- Set `CacheTTL: 0` to disable caching entirely

For high-traffic applications, the 2-minute default means at most ~1 validation call to HostedID per user every 2 minutes, while still detecting token revocation within a 2-minute window.

## License

Same as the HostedID project. See [LICENSE](../../LICENSE).
