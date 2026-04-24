package tzam

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// idpStub returns an httptest server that plays the validate/refresh roles.
// validateFn and refreshFn may be nil — in that case the route 401s.
func idpStub(
	t *testing.T,
	validateFn func(token string) (*TokenPayload, int),
	refreshFn func(cookie string) (string, int),
) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/validate":
			if validateFn == nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			tok := r.Header.Get("Authorization")
			if len(tok) > 7 {
				tok = tok[7:]
			}
			payload, status := validateFn(tok)
			w.WriteHeader(status)
			if payload != nil {
				_ = json.NewEncoder(w).Encode(payload)
			}
		case "/auth/refresh":
			if refreshFn == nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			c, _ := r.Cookie("refresh_token")
			value := ""
			if c != nil {
				value = c.Value
			}
			at, status := refreshFn(value)
			w.WriteHeader(status)
			if at != "" {
				_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": at})
			}
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestProxy_ValidSessionPassesThrough(t *testing.T) {
	srv := idpStub(t,
		func(tok string) (*TokenPayload, int) {
			if tok != "good" {
				return nil, http.StatusUnauthorized
			}
			return &TokenPayload{UserID: "u1", Email: "a@b"}, http.StatusOK
		},
		nil,
	)
	defer srv.Close()

	proxy := NewProxy(ProxyConfig{
		Config: Config{URL: srv.URL},
	})

	called := false
	handler := proxy.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if got := r.Header.Get(HeaderUserID); got != "u1" {
			t.Errorf("X-User-ID header = %q", got)
		}
		if user := UserFromContext(r.Context()); user == nil || user.Email != "a@b" {
			t.Errorf("context user = %+v", user)
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "good"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("wrapped handler not called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestProxy_ExpiredSessionTriggersRefresh(t *testing.T) {
	// First validate call: 401. Refresh returns "fresh". Second validate: OK.
	callCount := 0
	srv := idpStub(t,
		func(tok string) (*TokenPayload, int) {
			callCount++
			if tok == "fresh" {
				return &TokenPayload{UserID: "u1", Email: "a@b"}, http.StatusOK
			}
			return nil, http.StatusUnauthorized
		},
		func(cookie string) (string, int) {
			if cookie != "rt1" {
				return "", http.StatusUnauthorized
			}
			return "fresh", http.StatusOK
		},
	)
	defer srv.Close()

	proxy := NewProxy(ProxyConfig{Config: Config{URL: srv.URL}})

	handler := proxy.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "stale"})
	req.AddCookie(&http.Cookie{Name: RefreshCookie, Value: "rt1"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
	// Expect a refreshed session cookie on the response.
	foundSession := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie && c.Value == "fresh" {
			foundSession = true
		}
	}
	if !foundSession {
		t.Error("expected refreshed session cookie, got none")
	}
}

// TestProxy_RefreshRotation_RewritesBothCookies — when the IdP rotates
// the refresh token (common Tzam config for single-use refreshes), the
// proxy must write BOTH session AND refresh cookies back to the browser.
// Otherwise the browser keeps the old (now-consumed) refresh and the next
// /auth/refresh fails, causing a redirect loop to /auth/login ~15 min
// after a successful login.
func TestProxy_RefreshRotation_RewritesBothCookies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/validate":
			tok := r.Header.Get("Authorization")
			if len(tok) > 7 {
				tok = tok[7:]
			}
			if tok == "fresh" {
				_ = json.NewEncoder(w).Encode(TokenPayload{UserID: "u1", Email: "a@b"})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		case "/auth/refresh":
			// Rotating-refresh IdP: body has accessToken, Set-Cookie rotates refresh.
			http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: "rt-new", Path: "/"})
			_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": "fresh"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	proxy := NewProxy(ProxyConfig{Config: Config{URL: srv.URL}})
	handler := proxy.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "stale"})
	req.AddCookie(&http.Cookie{Name: RefreshCookie, Value: "rt-old"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}

	var gotSession, gotRefresh string
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie && c.MaxAge > 0 {
			gotSession = c.Value
		}
		if c.Name == RefreshCookie && c.MaxAge > 0 {
			gotRefresh = c.Value
		}
	}
	if gotSession != "fresh" {
		t.Errorf("session cookie = %q, want 'fresh'", gotSession)
	}
	if gotRefresh != "rt-new" {
		t.Errorf("refresh cookie = %q, want 'rt-new' (rotation must be propagated)", gotRefresh)
	}
}

// TestProxy_RefreshRotation_NoRotation_OnlySessionRewritten — when the
// IdP does NOT rotate the refresh, the proxy must leave the refresh
// cookie alone (otherwise a Set-Cookie with the same value + SameSite/
// Secure flags can mismatch the original and trip browsers).
func TestProxy_RefreshRotation_NoRotation_OnlySessionRewritten(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/validate":
			tok := r.Header.Get("Authorization")
			if len(tok) > 7 {
				tok = tok[7:]
			}
			if tok == "fresh" {
				_ = json.NewEncoder(w).Encode(TokenPayload{UserID: "u1", Email: "a@b"})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		case "/auth/refresh":
			// Non-rotating IdP: only access token comes back, refresh is untouched.
			_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": "fresh"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	proxy := NewProxy(ProxyConfig{Config: Config{URL: srv.URL}})
	handler := proxy.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "stale"})
	req.AddCookie(&http.Cookie{Name: RefreshCookie, Value: "rt-kept"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	var sessionSet, refreshSet bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie && c.MaxAge > 0 {
			sessionSet = true
		}
		if c.Name == RefreshCookie && c.MaxAge > 0 {
			refreshSet = true
		}
	}
	if !sessionSet {
		t.Error("expected session cookie to be rewritten")
	}
	if refreshSet {
		t.Error("refresh cookie should NOT be rewritten when IdP did not rotate")
	}
}

func TestProxy_RedirectsWhenNoCookies(t *testing.T) {
	srv := idpStub(t, nil, nil)
	defer srv.Close()

	proxy := NewProxy(ProxyConfig{Config: Config{URL: srv.URL}, LoginURL: "/signin"})
	handler := proxy.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("wrapped handler should not be reached")
	}))

	req := httptest.NewRequest(http.MethodGet, "/secret", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "/signin?redirect=%2Fsecret" {
		t.Errorf("unexpected redirect: %q", loc)
	}
}

func TestProxy_PublicRoutesSkipAuth(t *testing.T) {
	srv := idpStub(t, nil, nil)
	defer srv.Close()
	proxy := NewProxy(ProxyConfig{
		Config:       Config{URL: srv.URL},
		PublicRoutes: []string{"/", "/health", "/api/public"},
	})
	handler := proxy.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("public"))
	}))

	cases := []struct {
		path    string
		passes  bool
	}{
		{"/", true},
		{"/health", true},
		{"/api/public/ping", true},
		{"/api/private", false},
		{"/dashboard", false},
	}

	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if c.passes && rec.Code != http.StatusOK {
			t.Errorf("public %q: got %d, expected 200", c.path, rec.Code)
		}
		if !c.passes && rec.Code == http.StatusOK {
			t.Errorf("private %q: leaked through with 200", c.path)
		}
	}
}
