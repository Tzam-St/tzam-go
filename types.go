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
type LoginResult struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	User         User   `json:"user"`
}

// TokenPayload is the subset of JWT claims the IdP confirms via /auth/validate.
// It is intentionally narrow — rich claims live inside the JWT itself and
// should be verified with jose/JWKS if needed.
type TokenPayload struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
}
