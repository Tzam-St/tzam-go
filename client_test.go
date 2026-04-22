package tzam

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newMockServer spins up a test IdP that records the last request and
// replies with a scripted response.
type mockRequest struct {
	path    string
	method  string
	body    map[string]any
	cookie  string
	authz   string
}

type mockServer struct {
	*httptest.Server
	last mockRequest
}

func newMockServer(t *testing.T, handler http.HandlerFunc) *mockServer {
	t.Helper()
	ms := &mockServer{}
	ms.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{}
		if r.Body != nil {
			data, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(data, &body)
		}
		cookie := ""
		if c, err := r.Cookie("refresh_token"); err == nil {
			cookie = c.Value
		}
		ms.last = mockRequest{
			path:   r.URL.Path,
			method: r.Method,
			body:   body,
			cookie: cookie,
			authz:  r.Header.Get("Authorization"),
		}
		handler(w, r)
	}))
	t.Cleanup(ms.Close)
	return ms
}

func TestLogin_Success(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(LoginResult{
			AccessToken:  "at",
			RefreshToken: "rt",
			User:         User{ID: "u1", Email: "a@b", Name: "A"},
		})
	})
	c := NewClient(Config{URL: srv.URL, ClientID: "cid", ClientSecret: "sec"})

	res, err := c.Login(context.Background(), "a@b", "pw")
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if res.AccessToken != "at" || res.RefreshToken != "rt" || res.User.ID != "u1" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if srv.last.path != "/auth/login" || srv.last.method != http.MethodPost {
		t.Errorf("wrong request: %+v", srv.last)
	}
	if srv.last.body["email"] != "a@b" || srv.last.body["client_id"] != "cid" {
		t.Errorf("body missing fields: %+v", srv.last.body)
	}
}

func TestLogin_InvalidCredentialsIsSentinel(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"code":    CodeAuthInvalidCredentials,
			"message": "wrong password",
		})
	})
	c := NewClient(Config{URL: srv.URL})

	_, err := c.Login(context.Background(), "a@b", "pw")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("errors.Is should match ErrInvalidCredentials, got %v", err)
	}
	var api *APIError
	if !errors.As(err, &api) || api.Status != http.StatusUnauthorized {
		t.Errorf("expected APIError with 401, got %v", err)
	}
}

func TestValidateToken_ReturnsNilOn401(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"AUTH_TOKEN_EXPIRED"}`))
	})
	c := NewClient(Config{URL: srv.URL})

	payload, err := c.ValidateToken(context.Background(), "bad")
	if err != nil {
		t.Fatalf("expected nil error on 401, got %v", err)
	}
	if payload != nil {
		t.Errorf("expected nil payload, got %+v", payload)
	}
}

func TestValidateToken_Success(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(TokenPayload{UserID: "u1", Email: "a@b"})
	})
	c := NewClient(Config{URL: srv.URL})

	payload, err := c.ValidateToken(context.Background(), "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if payload.UserID != "u1" || payload.Email != "a@b" {
		t.Errorf("unexpected payload: %+v", payload)
	}
	if !strings.HasPrefix(srv.last.authz, "Bearer ") {
		t.Errorf("expected Bearer auth, got %q", srv.last.authz)
	}
}

func TestRefreshToken_SendsCookie(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"accessToken": "fresh"})
	})
	c := NewClient(Config{URL: srv.URL})

	at, err := c.RefreshToken(context.Background(), "rt-value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if at != "fresh" {
		t.Errorf("expected 'fresh', got %q", at)
	}
	if srv.last.cookie != "rt-value" {
		t.Errorf("refresh_token cookie not forwarded; got %q", srv.last.cookie)
	}
}

func TestLogout_BestEffort(t *testing.T) {
	srv := newMockServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	c := NewClient(Config{URL: srv.URL})

	if err := c.Logout(context.Background(), "at", "rt"); err != nil {
		t.Fatalf("logout should accept 204, got %v", err)
	}
}

func TestMagicLinkVerifyURL(t *testing.T) {
	c := NewClient(Config{URL: "https://tzam.online"})
	got := c.MagicLinkVerifyURL("ab cd")
	want := "https://tzam.online/auth/magic-link/verify?token=ab+cd"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNewClient_PanicsOnMissingURL(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on empty URL")
		}
	}()
	NewClient(Config{})
}
