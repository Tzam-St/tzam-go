package tzam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a thread-safe HTTP client for the Tzam IdP.
//
// Construct it with NewClient and reuse it across requests — under the
// hood it keeps a single *http.Client with connection pooling. All methods
// accept a context.Context so callers can carry deadlines and trace IDs.
type Client struct {
	cfg  Config
	http *http.Client
}

// NewClient builds a Client with sane defaults. Panics if URL is empty.
func NewClient(cfg Config) *Client {
	if cfg.URL == "" {
		panic("tzam: Config.URL is required")
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	timeout := cfg.HTTPTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: timeout},
	}
}

// Login exchanges email + password for access and refresh tokens.
//
// Merges Set-Cookie values (access_token / refresh_token) into the result
// when the body field is empty — the Tzam IdP intentionally omits
// refresh_token from the body (cookie-only) but older/alternative backends
// may ship both. Body values win when both are present.
func (c *Client) Login(ctx context.Context, email, password string) (*LoginResult, error) {
	body := map[string]any{
		"email":         email,
		"password":      password,
		"client_id":     c.cfg.ClientID,
		"client_secret": c.cfg.ClientSecret,
	}
	return c.postLoginShape(ctx, "/auth/login", body)
}

// Register creates a new app-scoped user and logs them in.
// Same cookie-merge contract as Login.
func (c *Client) Register(ctx context.Context, name, email, password string) (*LoginResult, error) {
	body := map[string]any{
		"name":         name,
		"email":        email,
		"password":     password,
		"clientId":     c.cfg.ClientID,
		"clientSecret": c.cfg.ClientSecret,
	}
	return c.postLoginShape(ctx, "/auth/register/app", body)
}

func (c *Client) postLoginShape(ctx context.Context, path string, body any) (*LoginResult, error) {
	status, data, cookies, err := c.postRaw(ctx, path, body, nil)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, decodeAPIErrorFromBytes(status, data)
	}
	var out LoginResult
	if len(data) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			return nil, fmt.Errorf("tzam: decode response: %w", err)
		}
	}
	mergeTokenCookies(&out.AccessToken, &out.RefreshToken, cookies)
	return &out, nil
}

// ValidateToken asks the IdP whether an access token is still valid.
// Returns nil payload without error when the token is expired/revoked —
// this matches the Node SDK's "silent failure" contract so middleware can
// attempt a refresh without treating every stale token as an exception.
func (c *Client) ValidateToken(ctx context.Context, token string) (*TokenPayload, error) {
	body := map[string]any{"token": token}
	headers := http.Header{"Authorization": {"Bearer " + token}}
	var out TokenPayload

	err := c.post(ctx, "/auth/validate", body, headers, &out)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			return nil, nil
		}
		return nil, err
	}
	return &out, nil
}

// RefreshSession swaps a refresh token for a fresh access (and possibly
// rotated refresh) token.
//
// Reads both tokens from the response body AND from Set-Cookie headers —
// works transparently against legacy body-only backends and modern
// cookie-only Tzam backends.
//
// RefreshResult.RefreshToken is non-empty only when the server rotated
// it. Callers relaying cookies to a browser should rewrite the refresh
// cookie only when it's non-empty and differs from the one they sent
// (see Proxy.Wrap for the canonical pattern).
func (c *Client) RefreshSession(ctx context.Context, refreshToken string) (*RefreshResult, error) {
	headers := http.Header{
		"Cookie": {"refresh_token=" + refreshToken},
	}
	status, data, cookies, err := c.postRaw(ctx, "/auth/refresh", nil, headers)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, decodeAPIErrorFromBytes(status, data)
	}
	var body struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
	}
	if len(data) > 0 {
		_ = json.Unmarshal(data, &body)
	}
	out := &RefreshResult{
		AccessToken:  body.AccessToken,
		RefreshToken: body.RefreshToken,
	}
	mergeTokenCookies(&out.AccessToken, &out.RefreshToken, cookies)
	return out, nil
}

// RefreshToken swaps a refresh token for a new access token.
//
// Deprecated: use RefreshSession instead. RefreshToken discards any
// rotated refresh token the server may have issued, which breaks
// rotating-refresh Tzam backends — the browser ends up keeping a
// consumed refresh and the next refresh call fails with 401. Retained
// for backward compatibility with callers pinned to v0.4.x.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	res, err := c.RefreshSession(ctx, refreshToken)
	if err != nil {
		return "", err
	}
	return res.AccessToken, nil
}

// Logout revokes the session tied to refreshToken. Best-effort — any error
// is returned to the caller but you should delete local cookies regardless.
func (c *Client) Logout(ctx context.Context, accessToken, refreshToken string) error {
	headers := http.Header{
		"Authorization": {"Bearer " + accessToken},
		"Cookie":        {"refresh_token=" + refreshToken},
	}
	return c.post(ctx, "/auth/logout", nil, headers, nil)
}

// RequestMagicLink asks the IdP to email a one-time login link to the user.
// Probes /auth/app-config first and returns ErrAppInactive /
// ErrMagicLinkMethodDisabled when the flow would be silently dropped —
// turning the IdP's 204-anyway contract into an actionable error.
func (c *Client) RequestMagicLink(ctx context.Context, email, redirect string) error {
	cfg, err := c.GetAuthMethods(ctx)
	if err != nil {
		return err
	}
	if !cfg.Active {
		return ErrAppInactive
	}
	if !cfg.Methods.MagicLink {
		return ErrMagicLinkMethodDisabled
	}
	body := map[string]any{
		"email":     email,
		"redirect":  redirect,
		"client_id": c.cfg.ClientID,
	}
	return c.post(ctx, "/auth/magic-link", body, nil, nil)
}

// RequestOTP sends a one-time numeric code to the user's email. Probes
// /auth/app-config first and returns ErrAppInactive / ErrOtpMethodDisabled
// when the flow would be silently dropped.
func (c *Client) RequestOTP(ctx context.Context, email string) error {
	cfg, err := c.GetAuthMethods(ctx)
	if err != nil {
		return err
	}
	if !cfg.Active {
		return ErrAppInactive
	}
	if !cfg.Methods.OTP {
		return ErrOtpMethodDisabled
	}
	body := map[string]any{
		"email":     email,
		"client_id": c.cfg.ClientID,
	}
	return c.post(ctx, "/auth/otp", body, nil, nil)
}

// VerifyOTP exchanges the emailed code for a full login result.
func (c *Client) VerifyOTP(ctx context.Context, email, code string) (*LoginResult, error) {
	body := map[string]any{"email": email, "code": code}
	var out LoginResult
	if err := c.post(ctx, "/auth/otp/verify", body, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MagicLinkVerifyURL returns the URL the user should be redirected to
// when they click the emailed magic link. Useful when the app has an
// intermediate /auth/callback page that prepares state before the redirect.
func (c *Client) MagicLinkVerifyURL(token string) string {
	return c.cfg.URL + "/auth/magic-link/verify?token=" + url.QueryEscape(token)
}

// ForgotPassword asks the IdP to email a password-reset link to the user.
// The IdP routes the email through the calling app's organization-scoped
// email provider when ClientID is configured (per-org branding, custom
// from-address). Server intentionally returns 204 even when the email is
// unknown — never reveals whether an account exists.
//
// Because the IdP also returns 204 when the app is inactive or has the
// email/password method disabled, this method probes /auth/app-config
// first and returns ErrAppInactive / ErrPasswordMethodDisabled before
// hitting the endpoint — so consumers get an actionable error instead
// of a silent no-op.
func (c *Client) ForgotPassword(ctx context.Context, email string) error {
	cfg, err := c.GetAuthMethods(ctx)
	if err != nil {
		return err
	}
	if !cfg.Active {
		return ErrAppInactive
	}
	if !cfg.Methods.Password {
		return ErrPasswordMethodDisabled
	}
	body := map[string]any{
		"email":    email,
		"clientId": c.cfg.ClientID,
	}
	return c.post(ctx, "/auth/forgot-password", body, nil, nil)
}

// ResetPassword completes a password change using the token delivered by
// ForgotPassword. Returns nil on success; an error on invalid/expired token.
func (c *Client) ResetPassword(ctx context.Context, token, newPassword string) error {
	body := map[string]any{
		"token":       token,
		"newPassword": newPassword,
	}
	return c.post(ctx, "/auth/reset-password", body, nil, nil)
}

// GetAuthMethods probes which auth methods are currently enabled for the
// configured ClientID. Use this to decide what UI to render —
// ForgotPassword (and other silent auth-email flows) always return 204,
// even when the method is disabled for the app, to avoid leaking which
// methods the app exposes. This endpoint is the only non-leaky way to
// find out.
func (c *Client) GetAuthMethods(ctx context.Context) (*AppConfig, error) {
	path := "/auth/app-config?client_id=" + url.QueryEscape(c.cfg.ClientID)
	var out AppConfig
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ─── internals ───────────────────────────────────────────────────────

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL+path, nil)
	if err != nil {
		return fmt.Errorf("tzam: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("tzam: %s %s: %w", http.MethodGet, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(resp.Body)
		return decodeAPIErrorFromBytes(resp.StatusCode, data)
	}

	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("tzam: decode response: %w", err)
	}
	return nil
}

func (c *Client) post(ctx context.Context, path string, body any, headers http.Header, out any) error {
	status, data, _, err := c.postRaw(ctx, path, body, headers)
	if err != nil {
		return err
	}
	if status >= 400 {
		return decodeAPIErrorFromBytes(status, data)
	}
	if out == nil || status == http.StatusNoContent {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("tzam: decode response: %w", err)
	}
	return nil
}

// postRaw issues a POST and returns the status, body bytes, and response
// Set-Cookie values. The body is fully drained and closed. Callers that
// only need a JSON payload use post; callers that also need to inspect
// Set-Cookie (Login / Register / RefreshSession) use this directly.
func (c *Client) postRaw(ctx context.Context, path string, body any, headers http.Header) (int, []byte, []*http.Cookie, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("tzam: marshal request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL+path, rdr)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("tzam: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("tzam: %s %s: %w", http.MethodPost, path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, resp.Cookies(), fmt.Errorf("tzam: read body: %w", err)
	}
	return resp.StatusCode, data, resp.Cookies(), nil
}

func decodeAPIErrorFromBytes(status int, data []byte) error {
	var payload struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(data, &payload)

	msg := payload.Message
	if msg == "" {
		msg = payload.Error
	}
	if msg == "" {
		msg = strings.TrimSpace(string(data))
	}
	return &APIError{Status: status, Code: payload.Code, Message: msg}
}

// Cookie names the Tzam IdP is known to use for tokens. Accept both
// snake_case (canonical, set by the Nest backend) and camelCase (defensive,
// some alt backends in the ecosystem diverge). Session constants in
// middleware.go (SessionCookie/RefreshCookie) are the names the SDK WRITES
// to the browser, not the ones the IdP SENDS — intentionally kept separate.
var (
	idpAccessCookies  = []string{"access_token", "accessToken"}
	idpRefreshCookies = []string{"refresh_token", "refreshToken"}
)

// mergeTokenCookies fills in *access / *refresh from Set-Cookie values
// when the caller's body-derived field is empty. Body wins on conflict —
// preserves explicit server response.
func mergeTokenCookies(access, refresh *string, cookies []*http.Cookie) {
	if *access == "" {
		*access = pickCookie(cookies, idpAccessCookies)
	}
	if *refresh == "" {
		*refresh = pickCookie(cookies, idpRefreshCookies)
	}
}

func pickCookie(cookies []*http.Cookie, names []string) string {
	for _, c := range cookies {
		if c == nil || c.Value == "" {
			continue
		}
		for _, n := range names {
			if c.Name == n {
				return c.Value
			}
		}
	}
	return ""
}
