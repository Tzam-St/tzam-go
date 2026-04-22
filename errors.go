package tzam

import (
	"errors"
	"fmt"
)

// Error codes returned by the Tzam IdP. Mirror the list documented at
// /docs/guides/sessions-and-refresh so client-side error handling can be
// consistent across Go, Node, and Python.
const (
	CodeAuthInvalidCredentials = "AUTH_INVALID_CREDENTIALS"
	CodeAuthAccountInactive    = "AUTH_ACCOUNT_INACTIVE"
	CodeAuthUserNotRegistered  = "AUTH_USER_NOT_REGISTERED"
	CodeAuthEmailExists        = "AUTH_EMAIL_EXISTS"
	CodeAuthTokenInvalid       = "AUTH_TOKEN_INVALID"
	CodeAuthTokenExpired       = "AUTH_TOKEN_EXPIRED"
	CodeAuthSessionRevoked     = "AUTH_SESSION_REVOKED"
	CodeAuthRefreshFailed      = "AUTH_REFRESH_FAILED"

	CodeOAuthProviderDisabled = "OAUTH_PROVIDER_DISABLED"
	CodeOAuthCodeInvalid      = "OAUTH_CODE_INVALID"
	CodeOAuthCodeExpired      = "OAUTH_CODE_EXPIRED"

	CodeAppClientInvalid   = "APP_CLIENT_INVALID"
	CodeAppRedirectInvalid = "APP_REDIRECT_INVALID"
)

// APIError wraps a structured error returned by the IdP. The Code field
// matches the constants above and can be compared with errors.Is or
// direct equality — see ErrInvalidCredentials and friends below.
type APIError struct {
	Status  int    // HTTP status code
	Code    string // Tzam error code (may be empty if IdP returned a generic message)
	Message string // Human-readable message
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("tzam: %s (%d) %s", e.Code, e.Status, e.Message)
	}
	return fmt.Sprintf("tzam: HTTP %d %s", e.Status, e.Message)
}

// Is enables errors.Is comparisons against the sentinel errors below.
// Two APIErrors match if their Code fields are equal — Status and Message
// are ignored since the IdP may change wording without breaking contract.
func (e *APIError) Is(target error) bool {
	var other *APIError
	if errors.As(target, &other) {
		return e.Code != "" && e.Code == other.Code
	}
	return false
}

// Sentinel errors for common failure modes. Compare with errors.Is.
var (
	ErrInvalidCredentials = &APIError{Code: CodeAuthInvalidCredentials}
	ErrAccountInactive    = &APIError{Code: CodeAuthAccountInactive}
	ErrUserNotRegistered  = &APIError{Code: CodeAuthUserNotRegistered}
	ErrEmailExists        = &APIError{Code: CodeAuthEmailExists}
	ErrTokenInvalid       = &APIError{Code: CodeAuthTokenInvalid}
	ErrTokenExpired       = &APIError{Code: CodeAuthTokenExpired}
	ErrSessionRevoked     = &APIError{Code: CodeAuthSessionRevoked}
	ErrRefreshFailed      = &APIError{Code: CodeAuthRefreshFailed}
)
