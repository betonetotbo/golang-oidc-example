package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/patrickmn/go-cache"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type (
	TokensContextValueType string

	OidcConfig struct {
		Issuer       string
		ClientId     string
		ClientSecret string
		RedirectUri  string
		Scopes       []string
	}

	Oidc struct {
		cfg        *OidcConfig
		verifier   *oidc.IDTokenVerifier
		oauth2Cfg  *oauth2.Config
		m          sync.Mutex
		inited     bool
		sidBanlist *cache.Cache
	}

	Tokens struct {
		IDToken      string
		AccessToken  string
		RefreshToken string
	}
)

var (
	TokensContextValue TokensContextValueType = "oidc-tokens"
)

func NewOidc(cfg *OidcConfig) *Oidc {
	return &Oidc{
		cfg:        cfg,
		sidBanlist: cache.New(24*time.Hour, time.Hour),
	}
}

func (t *Tokens) GetClaims(token string) map[string]any {
	return parseClaims(token)
}

func (o *Oidc) init() {
	if o.inited {
		return
	}
	o.m.Lock()
	defer o.m.Unlock()

	if o.inited {
		return
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, o.cfg.Issuer)
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: o.cfg.ClientId,
	}
	o.verifier = provider.Verifier(oidcConfig)

	o.oauth2Cfg = &oauth2.Config{
		ClientID:     o.cfg.ClientId,
		ClientSecret: o.cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  o.cfg.RedirectUri,
		Scopes:       o.cfg.Scopes,
	}

	o.inited = true
}

func (o *Oidc) checkToken(r *http.Request) (bool, *Tokens) {
	rawIDToken, err := r.Cookie("id_token")
	if errors.Is(err, http.ErrNoCookie) {
		return false, nil
	}
	idToken, err := o.verifier.Verify(r.Context(), rawIDToken.Value)
	if err != nil {
		log.Println("Invalid IDToken")
		return false, nil
	}

	rawAccessToken, err := r.Cookie("access_token")
	if errors.Is(err, http.ErrNoCookie) {
		return false, nil
	}

	rawRefreshToken, err := r.Cookie("refresh_token")
	if errors.Is(err, http.ErrNoCookie) {
		return false, nil
	}

	err = idToken.VerifyAccessToken(rawAccessToken.Value)
	if err != nil {
		return false, nil
	}
	return true, &Tokens{
		IDToken:      rawIDToken.Value,
		AccessToken:  rawAccessToken.Value,
		RefreshToken: rawRefreshToken.Value,
	}
}

func (o *Oidc) IsAuthorized(r *http.Request) (bool, *Tokens) {
	o.init()
	authorized, tokens := o.checkToken(r)
	if !authorized {
		return false, nil
	}

	claims := parseClaims(tokens.AccessToken)
	sid := claims["sid"].(string)
	if _, found := o.sidBanlist.Get(sid); found {
		log.Printf("Token valid but banned SID: %s", sid)
		return false, nil
	}
	return true, tokens
}

func (o *Oidc) NewMiddleware(ignore func(*http.Request) bool, redirectOnDenied string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !ignore(r) {
				o.init()
				ok, tokens := o.IsAuthorized(r)
				if !ok {
					if redirectOnDenied != "" {
						http.Redirect(w, r, redirectOnDenied, http.StatusFound)
					} else {
						w.WriteHeader(http.StatusUnauthorized)
					}
					return
				}
				ctx := r.Context()
				r = r.WithContext(context.WithValue(ctx, TokensContextValue, tokens))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (o *Oidc) RedirectAuth(w http.ResponseWriter, r *http.Request) {
	o.init()

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

	http.Redirect(w, r, o.oauth2Cfg.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

func (o *Oidc) ExchangeToken(redirectTo string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		o.init()

		state, err := r.Cookie("state")
		if err != nil {
			http.Error(w, "state not found", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("state") != state.Value {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := o.oauth2Cfg.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := o.verifier.Verify(r.Context(), rawIDToken)
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

		claims := parseClaims(oauth2Token.AccessToken)
		log.Printf("Token exchanged for SID: %s", claims["sid"])

		http.Redirect(w, r, redirectTo, http.StatusFound)
	}
}

func (o *Oidc) BackChannelLogout(w http.ResponseWriter, r *http.Request) {
	o.init()

	// TODO verificar a assinatura, etc...
	rawLogoutToken := r.FormValue("logout_token")
	claims := parseClaims(rawLogoutToken)

	exp := claims["exp"].(float64)
	expTime := time.Unix(int64(exp), 0)
	sid := claims["sid"].(string)
	o.sidBanlist.Set(sid, claims["sub"], expTime.Sub(time.Now()))

	log.Printf("BackChannelLogout: SID %s banned", sid)
}

func (o *Oidc) Logout(redirectTo string, endSession bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if endSession {
			idTokenHint := url.QueryEscape(r.Context().Value(TokensContextValue).(*Tokens).IDToken)
			logoutUrl := fmt.Sprintf("%s/protocol/openid-connect/logout?id_token_hint=%s&post_logout_redirect_uri=%s", o.cfg.Issuer, idTokenHint, redirectTo)
			http.Redirect(w, r, logoutUrl, http.StatusFound)
		} else {
			setCookie(w, r, "acceess_token", "")
			setCookie(w, r, "refresh_token", "")
			setCookie(w, r, "id_token", "")
			http.Redirect(w, r, redirectTo, http.StatusFound)
		}
	}
}
