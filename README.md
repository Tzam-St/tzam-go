# Tzam Go SDK

Official Go client for the [Tzam Identity Provider](https://tzam.online).

**Tzam** (צם) — Hebrew for *"to watch and protect"*.

Zero external dependencies. Stdlib only. One `*http.Client` under the hood, reused across requests, safe for concurrent use. Cookie contract identical to the [`@tzam-st/tzam`](https://www.npmjs.com/package/@tzam-st/tzam) Next.js package so Go and Node services can share sessions on the same domain.

## Install

```bash
go get github.com/Tzam-St/tzam-go
```

## Client usage

```go
package main

import (
    "context"
    "log"

    "github.com/Tzam-St/tzam-go"
)

func main() {
    client := tzam.NewClient(tzam.Config{
        URL:          "https://tzam.online",
        ClientID:     "your-client-id",
        ClientSecret: "your-client-secret",
    })

    result, err := client.Login(context.Background(), "user@example.com", "password")
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("logged in as %s (token=%s)", result.User.Email, result.AccessToken)
}
```

### Available methods

| Method | Purpose |
|---|---|
| `Login(ctx, email, password)` | Password login |
| `Register(ctx, name, email, password)` | App user registration |
| `ValidateToken(ctx, accessToken)` | Confirm a token is valid (returns `nil, nil` when expired/revoked) |
| `RefreshToken(ctx, refreshToken)` | Exchange refresh for new access token |
| `Logout(ctx, accessToken, refreshToken)` | Revoke the session |
| `RequestMagicLink(ctx, email, redirect)` | Email a one-time login link |
| `RequestOTP(ctx, email)` | Email a one-time numeric code |
| `VerifyOTP(ctx, email, code)` | Exchange OTP for tokens |
| `MagicLinkVerifyURL(token)` | Build the verify URL for an emailed magic link |

### Error handling

All errors from the IdP wrap `*tzam.APIError`. Compare with `errors.Is`:

```go
_, err := client.Login(ctx, email, password)
if errors.Is(err, tzam.ErrInvalidCredentials) {
    // show "wrong email or password"
}
if errors.Is(err, tzam.ErrAccountInactive) {
    // show "account disabled, contact admin"
}
```

Sentinel errors: `ErrInvalidCredentials`, `ErrAccountInactive`, `ErrUserNotRegistered`, `ErrEmailExists`, `ErrTokenInvalid`, `ErrTokenExpired`, `ErrSessionRevoked`, `ErrRefreshFailed`.

## HTTP middleware

For services that need to protect routes with a cookie-based session, use the `Proxy` — validates `session` cookie, auto-refreshes via `refresh_token`, injects user into request context and headers.

```go
package main

import (
    "fmt"
    "net/http"

    "github.com/Tzam-St/tzam-go"
)

func main() {
    proxy := tzam.NewProxy(tzam.ProxyConfig{
        Config: tzam.Config{
            URL:          "https://tzam.online",
            ClientID:     "your-client-id",
            ClientSecret: "your-client-secret",
        },
        PublicRoutes: []string{"/", "/auth/login", "/api/public"},
        LoginURL:     "/auth/login",
    })

    mux := http.NewServeMux()
    mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
        user := tzam.UserFromContext(r.Context())
        fmt.Fprintf(w, "Hi, %s (id=%s)", user.Email, user.UserID)
    })

    http.ListenAndServe(":3000", proxy.Wrap(mux))
}
```

Inside protected handlers:
- `tzam.UserFromContext(ctx)` → `*tzam.TokenPayload`
- `r.Header.Get(tzam.HeaderUserID)` → `"u1"`
- `r.Header.Get(tzam.HeaderUserEmail)` → `"user@example.com"`

### Cookies written by the middleware

Only when a refresh succeeds — the middleware writes a new `session` cookie with the refreshed access token. It never writes the `refresh_token` cookie; that is set by the login handler when the session is first established.

## Framework adapters

The middleware implements the standard `func(http.Handler) http.Handler` pattern, so it works with any router that accepts net/http middleware.

### Gin

```go
import (
    "github.com/gin-gonic/gin"
    "github.com/Tzam-St/tzam-go"
)

r := gin.Default()
r.Use(func(c *gin.Context) {
    proxy.Wrap(c.Next).ServeHTTP(c.Writer, c.Request)
    // Or via adapter.Wrap(proxy.Wrap, c) — see examples/gin
})
```

### Echo

```go
import (
    "github.com/labstack/echo/v4"
    "github.com/Tzam-St/tzam-go"
)

e := echo.New()
e.Use(echo.WrapMiddleware(proxy.Wrap))
```

### Chi / net/http

Works as-is:

```go
r := chi.NewRouter()
r.Use(proxy.Wrap)
```

## Configuration

```go
type Config struct {
    URL          string         // e.g. "https://tzam.online"
    ClientID     string         // Application.clientId
    ClientSecret string         // Application.clientSecret
    HTTPTimeout  time.Duration  // default 10s
}

type ProxyConfig struct {
    Config                      // embedded

    PublicRoutes []string       // default ["/", "/auth/login", "/auth/register", "/api/auth"]
    LoginURL     string         // default "/auth/login"
    Secure       *bool          // default true (set to false for http:// dev)
    CookiePath   string         // default "/"
}
```

## Concurrency

`*tzam.Client` and `*tzam.Proxy` are safe for concurrent use. Build them once at app startup and share across goroutines.

## Testing

```bash
go test ./...
```

The suite uses `httptest.NewServer` to stub the IdP — no network access required. Cover client methods and the proxy validate/refresh/redirect cascade.

## License

MIT © Tzam-St
