package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/betonetotbo/golang-oidc-example/internal/auth"
	"github.com/betonetotbo/golang-oidc-example/internal/html"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var (
	port         = os.Getenv("PORT")
	issuer       = os.Getenv("ISSUER")
	clientID     = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
)

func main() {
	authOidc := auth.NewOidc(&auth.OidcConfig{
		Issuer:       issuer,
		ClientId:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid"},
		RedirectUri:  fmt.Sprintf("http://localhost:%s/auth", port),
	})

	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(authOidc.NewMiddleware(func(r *http.Request) bool {
		switch r.URL.Path {
		case "/", "/login", "/auth", "/backchannel-logout":
			return true
		}
		return false
	}, "/"))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, tokens := authOidc.IsAuthorized(r)
		data := map[string]any{}
		if tokens != nil {
			data["name"] = tokens.GetClaims(tokens.AccessToken)["name"].(string)
			data["authorized"] = true
		}

		err := html.RenderTemplate(w, r, "index", data)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
		}
	})
	r.Get("/login", authOidc.RedirectAuth)
	r.Get("/auth", authOidc.ExchangeToken("/protected"))
	r.Post("/backchannel-logout", authOidc.BackChannelLogout)
	r.Get("/protected", func(w http.ResponseWriter, r *http.Request) {
		tokens := r.Context().Value(auth.TokensContextValue).(*auth.Tokens)

		claims := jwt.MapClaims{}
		_, _, _ = new(jwt.Parser).ParseUnverified(tokens.AccessToken, claims)
		rawValue, _ := json.MarshalIndent(claims, "", "   ")
		claims["rawValue"] = string(rawValue)

		err := html.RenderTemplate(w, r, "protected", claims)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(err.Error()))
		}
	})
	r.Get("/logout", authOidc.Logout("/", false))
	r.Get("/signout", authOidc.Logout(fmt.Sprintf("http://localhost:%s", port), true))

	log.Printf("listening on http://localhost:%s/", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
