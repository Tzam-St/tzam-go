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
func (c *Client) Login(ctx context.Context, email, password string) (*LoginResult, error) {
	body := map[string]any{
		"email":         email,
		"password":      password,
		"client_id":     c.cfg.ClientID,
		"client_secret": c.cfg.ClientSecret,
	}
	var out LoginResult
	if err := c.post(ctx, "/auth/login", body, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Register creates a new app-scoped user and logs them in.
func (c *Client) Register(ctx context.Context, name, email, password string) (*LoginResult, error) {
	body := map[string]any{
		"name":         name,
		"email":        email,
		"password":     password,
		"clientId":     c.cfg.ClientID,
		"clientSecret": c.cfg.ClientSecret,
	}
	var out LoginResult
	if err := c.post(ctx, "/auth/register/app", body, nil, &out); err != nil {
		return nil, err
	}
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

// RefreshToken swaps a refresh token for a new access token. The refresh
// token itself is sent in a Cookie header to match how browsers do it.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	headers := http.Header{
		"Cookie": {"refresh_token=" + refreshToken},
	}
	var out struct {
		AccessToken string `json:"accessToken"`
	}
	if err := c.post(ctx, "/auth/refresh", nil, headers, &out); err != nil {
		return "", err
	}
	return out.AccessToken, nil
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
// Returns nil on 200 and 204.
func (c *Client) RequestMagicLink(ctx context.Context, email, redirect string) error {
	body := map[string]any{
		"email":     email,
		"redirect":  redirect,
		"client_id": c.cfg.ClientID,
	}
	return c.post(ctx, "/auth/magic-link", body, nil, nil)
}

// RequestOTP sends a one-time numeric code to the user's email.
func (c *Client) RequestOTP(ctx context.Context, email string) error {
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
func (c *Client) ForgotPassword(ctx context.Context, email string) error {
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
		return decodeAPIError(resp)
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
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("tzam: marshal request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL+path, rdr)
	if err != nil {
		return fmt.Errorf("tzam: build request: %w", err)
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
		return fmt.Errorf("tzam: %s %s: %w", http.MethodPost, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return decodeAPIError(resp)
	}

	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("tzam: decode response: %w", err)
	}
	return nil
}

func decodeAPIError(resp *http.Response) error {
	var payload struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &payload)

	msg := payload.Message
	if msg == "" {
		msg = payload.Error
	}
	if msg == "" {
		msg = strings.TrimSpace(string(data))
	}
	return &APIError{Status: resp.StatusCode, Code: payload.Code, Message: msg}
}
