// Package tzam is the official Go SDK for the Tzam Identity Provider.
//
// It provides a stdlib-only HTTP client for login/register/validate/refresh/
// logout/magic-link/OTP, plus a net/http middleware that validates cookie
// sessions and auto-refreshes expired access tokens — identical cookie
// contract to the Next.js package @tzam-st/tzam, so Go and Node services
// can share sessions on the same domain.
package tzam

import "time"

// Config carries the IdP connection details. ClientSecret may be empty for
// public clients (SPAs, mobile) that use PKCE instead.
type Config struct {
	// URL is the base URL of the Tzam IdP (no trailing slash).
	// Example: "https://tzam.online".
	URL string

	// ClientID is the Application.clientId registered in the admin panel.
	ClientID string

	// ClientSecret is the Application.clientSecret. Required for password/OAuth flows.
	ClientSecret string

	// HTTPTimeout overrides the default 10s request timeout.
	HTTPTimeout time.Duration
}

// User is the subset of user data returned by login/register/OAuth callback.
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// LoginResult is returned by Login, Register, and VerifyOTP.
//
// Modern Tzam backends deliver tokens via Set-Cookie (refresh_token is
// never in the body for security). The client merges cookie values into
// this struct when the body field is empty so callers relaying tokens to
// a browser get consistent results regardless of backend version.
type LoginResult struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	User         User   `json:"user"`
}

// RefreshResult carries the tokens returned by RefreshSession.
//
// AccessToken is always populated on success. RefreshToken is non-empty
// only when the server rotated it (cookie-rotating IdPs return the new
// value via Set-Cookie). Callers relaying cookies to a browser should
// rewrite the refresh cookie only when it's non-empty and differs from
// the one they sent — see Proxy.Wrap for the canonical pattern.
type RefreshResult struct {
	AccessToken  string
	RefreshToken string
}

// TokenPayload is the subset of JWT claims the IdP confirms via /auth/validate.
// It is intentionally narrow — rich claims live inside the JWT itself and
// should be verified with jose/JWKS if needed.
type TokenPayload struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
}

// OAuthMethods tells which third-party login buttons are currently enabled
// for the calling app.
type OAuthMethods struct {
	Github bool `json:"github"`
	Google bool `json:"google"`
}

// AppMethods describes which auth entry points are active for the app.
type AppMethods struct {
	Password  bool         `json:"password"`
	MagicLink bool         `json:"magicLink"`
	OTP       bool         `json:"otp"`
	OAuth     OAuthMethods `json:"oauth"`
}

// AppConfig is returned by GetAuthMethods. It lets the client decide
// what auth UI to render without relying on forgot-password / magic-link
// status codes — those endpoints are silent by design so they can't be
// probed to enumerate which methods an app exposes.
type AppConfig struct {
	ClientID string     `json:"clientId"`
	Active   bool       `json:"active"`
	Methods  AppMethods `json:"methods"`
}
