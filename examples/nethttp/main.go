// Example: protecting a plain net/http server with the Tzam proxy.
//
//	go run ./examples/nethttp
//	curl -v http://localhost:3000/dashboard   # → 303 /auth/login?redirect=%2Fdashboard
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	tzam "github.com/Tzam-St/tzam-go"
)

func main() {
	proxy := tzam.NewProxy(tzam.ProxyConfig{
		Config: tzam.Config{
			URL:          env("TZAM_URL", "https://tzam.online"),
			ClientID:     os.Getenv("TZAM_CLIENT_ID"),
			ClientSecret: os.Getenv("TZAM_CLIENT_SECRET"),
		},
		PublicRoutes: []string{"/", "/health", "/auth/login", "/auth/callback"},
		LoginURL:     "/auth/login",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		user := tzam.UserFromContext(r.Context())
		fmt.Fprintf(w, "Hi %s — your ID is %s\n", user.Email, user.UserID)
	})

	log.Println("listening on :3000")
	log.Fatal(http.ListenAndServe(":3000", proxy.Wrap(mux)))
}

func env(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
