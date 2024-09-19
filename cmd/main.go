package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/betonetotbo/golang-oidc-example/internal/html"
	"github.com/dgrijalva/jwt-go"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	port         = os.Getenv("PORT")
	issuer       = os.Getenv("ISSUER")
	clientID     = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
)

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

func main() {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  fmt.Sprintf("http://localhost:%s/auth", port),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		state, err := randString(16)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		nonce, err := randString(16)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		setCookie(w, r, "state", state)
		setCookie(w, r, "nonce", nonce)

		http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
	})

	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		state, err := r.Cookie("state")
		if err != nil {
			http.Error(w, "state not found", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("state") != state.Value {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		nonce, err := r.Cookie("nonce")
		if err != nil {
			http.Error(w, "nonce not found", http.StatusBadRequest)
			return
		}
		if idToken.Nonce != nonce.Value {
			http.Error(w, "nonce did not match", http.StatusBadRequest)
			return
		}

		setCookie(w, r, "access_token", oauth2Token.AccessToken)
		setCookie(w, r, "refresh_token", oauth2Token.RefreshToken)
		setCookie(w, r, "id_token", rawIDToken)

		http.Redirect(w, r, "/protected", http.StatusFound)
	})

	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		rawIDToken, err := r.Cookie("id_token")
		if errors.Is(err, http.ErrNoCookie) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		idToken, err := verifier.Verify(r.Context(), rawIDToken.Value)
		if err != nil {
			log.Println("Invalid IDToken")
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		rawAccessToken, err := r.Cookie("access_token")
		if errors.Is(err, http.ErrNoCookie) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		err = idToken.VerifyAccessToken(rawAccessToken.Value)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		claims := jwt.MapClaims{}
		_, _, _ = new(jwt.Parser).ParseUnverified(rawAccessToken.Value, claims)
		rawValue, _ := json.MarshalIndent(claims, "", "   ")
		claims["rawValue"] = string(rawValue)

		w.WriteHeader(http.StatusOK)
		html.RenderTemplate(w, r, "protected", claims)
	})

	http.HandleFunc("/backchannel-logout", func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.FormValue("logout_token"))
	})

	log.Printf("listening on http://localhost:%s/", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
