package tzam

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// Cookie names used by the middleware. They match the Next.js SDK so Go
// and Node services can share a session on the same domain.
const (
	SessionCookie = "session"
	RefreshCookie = "refresh_token"
)

// Header names injected into the request before it reaches the wrapped
// handler. Downstream handlers read these instead of decoding the JWT.
const (
	HeaderUserID    = "X-User-ID"
	HeaderUserEmail = "X-User-Email"
)

// ContextKey is the type used for the user payload stored in the request
// context. Use tzam.UserFromContext to retrieve it from handlers.
type ContextKey struct{}

// UserFromContext returns the validated user payload for the current request.
// Returns nil when the request did not pass through a Tzam proxy.
func UserFromContext(ctx context.Context) *TokenPayload {
	v, _ := ctx.Value(ContextKey{}).(*TokenPayload)
	return v
}

// ProxyConfig configures the HTTP middleware.
type ProxyConfig struct {
	Config

	// PublicRoutes is a list of path prefixes that skip authentication.
	// Default: ["/", "/auth/login", "/auth/register", "/api/auth"].
	// A "/" entry matches only the exact root path, not every request.
	PublicRoutes []string

	// LoginURL is where unauthenticated users are redirected. The current
	// path is appended as ?redirect=<path> so the login page can send the
	// user back after a successful sign-in.
	// Default: "/auth/login".
	LoginURL string

	// Secure controls the Secure flag on refreshed session cookies.
	// Default: true. Set false for local development over plain HTTP.
	Secure *bool

	// CookiePath applies to the refreshed session cookie. Default: "/".
	CookiePath string
}

// Proxy is an HTTP middleware that validates session cookies, performs
// silent refreshes, and attaches the user payload to request context.
type Proxy struct {
	client       *Client
	publicRoutes []string
	loginURL     string
	secure       bool
	cookiePath   string
}

// NewProxy builds a Proxy with sane defaults.
func NewProxy(cfg ProxyConfig) *Proxy {
	routes := cfg.PublicRoutes
	if routes == nil {
		routes = []string{"/", "/auth/login", "/auth/register", "/api/auth"}
	}
	loginURL := cfg.LoginURL
	if loginURL == "" {
		loginURL = "/auth/login"
	}
	secure := true
	if cfg.Secure != nil {
		secure = *cfg.Secure
	}
	cookiePath := cfg.CookiePath
	if cookiePath == "" {
		cookiePath = "/"
	}
	return &Proxy{
		client:       NewClient(cfg.Config),
		publicRoutes: routes,
		loginURL:     loginURL,
		secure:       secure,
		cookiePath:   cookiePath,
	}
}

// Wrap returns a new handler that authenticates every request before
// delegating to next. Matches the standard net/http middleware signature.
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("/dashboard", dashboardHandler)
//	http.ListenAndServe(":3000", proxy.Wrap(mux))
func (p *Proxy) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.isPublic(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		payload := p.authenticate(w, r)
		if payload == nil {
			// Already redirected / responded.
			return
		}

		r.Header.Set(HeaderUserID, payload.UserID)
		r.Header.Set(HeaderUserEmail, payload.Email)
		ctx := context.WithValue(r.Context(), ContextKey{}, payload)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (p *Proxy) isPublic(path string) bool {
	for _, route := range p.publicRoutes {
		if route == "/" {
			if path == "/" {
				return true
			}
			continue
		}
		if strings.HasPrefix(path, route) {
			return true
		}
	}
	return false
}

// authenticate returns the validated payload, or nil if the request has
// already been redirected to login. It performs the validate → refresh →
// redirect cascade identical to the Next.js proxy.
func (p *Proxy) authenticate(w http.ResponseWriter, r *http.Request) *TokenPayload {
	ctx := r.Context()
	session, refresh := readSessionCookies(r)

	// Happy path — valid session cookie.
	if session != "" {
		if payload, _ := p.client.ValidateToken(ctx, session); payload != nil {
			return payload
		}
	}

	// Attempt refresh when the session is bad but a refresh token exists.
	if refresh != "" {
		res, err := p.client.RefreshSession(ctx, refresh)
		if err == nil && res != nil && res.AccessToken != "" {
			if payload, _ := p.client.ValidateToken(ctx, res.AccessToken); payload != nil {
				p.setSessionCookie(w, res.AccessToken, 15*60)
				// Rewrite refresh cookie only when the IdP actually rotated
				// it. Skipping the no-op rewrite avoids unnecessary
				// Set-Cookie churn and dodges corner cases where the rewritten
				// cookie would differ from the browser's original by SameSite
				// or Secure flags on the same value.
				if res.RefreshToken != "" && res.RefreshToken != refresh {
					p.setRefreshCookie(w, res.RefreshToken)
				}
				return payload
			}
		}
	}

	// Give up — clear cookies and redirect.
	p.clearSessionCookies(w)
	p.redirectToLogin(w, r)
	return nil
}

func readSessionCookies(r *http.Request) (session, refresh string) {
	if c, err := r.Cookie(SessionCookie); err == nil {
		session = c.Value
	}
	if c, err := r.Cookie(RefreshCookie); err == nil {
		refresh = c.Value
	}
	return
}

func (p *Proxy) setSessionCookie(w http.ResponseWriter, token string, maxAgeSeconds int) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     p.cookiePath,
		HttpOnly: true,
		Secure:   p.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAgeSeconds,
	})
}

// setRefreshCookie propagates a rotated refresh token from the IdP to the
// browser. Uses a 7-day MaxAge — matches the Tzam IdP default for
// non-remembered sessions. When the caller has its own login handler that
// wrote the initial refresh cookie with a different MaxAge (e.g. 30 days
// for "remember me"), the rotated cookie here resets to 7 days; callers
// who need to preserve the original can set the cookie themselves from
// RefreshSession's return value.
func (p *Proxy) setRefreshCookie(w http.ResponseWriter, token string) {
	const sevenDays = 7 * 24 * 60 * 60
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookie,
		Value:    token,
		Path:     p.cookiePath,
		HttpOnly: true,
		Secure:   p.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   sevenDays,
	})
}

func (p *Proxy) clearSessionCookies(w http.ResponseWriter) {
	for _, name := range []string{SessionCookie, RefreshCookie} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     p.cookiePath,
			HttpOnly: true,
			Secure:   p.secure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   -1,
		})
	}
}

func (p *Proxy) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	dest := p.loginURL + "?redirect=" + url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, dest, http.StatusSeeOther)
}
