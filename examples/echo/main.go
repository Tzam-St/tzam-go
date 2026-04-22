// Example: protecting Echo routes with the Tzam proxy.
//
// Not compiled by the main module. To run:
//
//	cd examples/echo && go mod init example && go get github.com/labstack/echo/v4 && go run .
package main

import (
	"net/http"
	"os"

	"github.com/labstack/echo/v4"
	tzam "github.com/Tzam-St/tzam-go"
)

func main() {
	proxy := tzam.NewProxy(tzam.ProxyConfig{
		Config: tzam.Config{
			URL:          os.Getenv("TZAM_URL"),
			ClientID:     os.Getenv("TZAM_CLIENT_ID"),
			ClientSecret: os.Getenv("TZAM_CLIENT_SECRET"),
		},
	})

	e := echo.New()

	// echo.WrapMiddleware adapts any net/http middleware to Echo.
	e.GET("/health", func(c echo.Context) error { return c.String(200, "ok") })
	e.GET("/dashboard", func(c echo.Context) error {
		user := tzam.UserFromContext(c.Request().Context())
		return c.JSON(http.StatusOK, map[string]string{
			"email": user.Email,
			"id":    user.UserID,
		})
	}, echo.WrapMiddleware(proxy.Wrap))

	_ = e.Start(":3000")
}
