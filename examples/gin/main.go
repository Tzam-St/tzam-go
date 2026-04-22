// Example: protecting Gin routes with the Tzam proxy.
//
// This file is NOT compiled by the main module — it would require a
// dependency on gin that the core SDK does not want. To run:
//
//	cd examples/gin && go mod init example && go get github.com/gin-gonic/gin && go run .
package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
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

	// gin.WrapH converts http.Handler → gin.HandlerFunc. We build an
	// http.Handler per request that runs the proxy and, on success,
	// re-enters the Gin chain via c.Next().
	authed := func(c *gin.Context) {
		h := proxy.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Replace Gin's request with the one carrying x-user-* headers
			// and the enriched context, then continue the Gin chain.
			c.Request = r
			c.Next()
		}))
		h.ServeHTTP(c.Writer, c.Request)
	}

	r := gin.Default()
	r.GET("/health", func(c *gin.Context) { c.String(200, "ok") })

	secured := r.Group("/", authed)
	secured.GET("/dashboard", func(c *gin.Context) {
		user := tzam.UserFromContext(c.Request.Context())
		c.JSON(200, gin.H{"email": user.Email, "id": user.UserID})
	})

	_ = r.Run(":3000")
}
