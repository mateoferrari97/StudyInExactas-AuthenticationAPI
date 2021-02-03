package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"os"
)

var (
	ErrTokenNotFound        = errors.New("auth: token not found")
	ErrIDTokenNotFound      = errors.New("auth: id token not found")
	ErrAuthenticationFailed = errors.New("auth: authentication failed")
)

type Authenticator struct {
	provider *oidc.Provider
	config   oauth2.Config
}

func NewAuthenticator(env string) (*Authenticator, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "https://food4everyone.us.auth0.com/")
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	baseURL := "http://localhost:8080"
	if env == "production" {
		baseURL = os.Getenv("BASE_URL")
	}

	conf := oauth2.Config{
		ClientID:     "qHcV8N1iSntNMbZGxG6wP38sofmEK9aB",
		ClientSecret: "YoEyXYMjjXf82CjoAYzOaNqJwFyDz5162kqBSuSI9kzqAEPwcBkjFM31s_JAZ8JG",
		RedirectURL:  fmt.Sprintf("%s/login/callback", baseURL),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &Authenticator{
		provider: provider,
		config:   conf,
	}, nil
}

type AuthenticationURL struct {
	state string
	url   string
}

func (au *AuthenticationURL) String() string {
	return au.url
}

func (au *AuthenticationURL) State() string {
	return au.state
}

func (a *Authenticator) CreateAuthenticationURL() (*AuthenticationURL, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	CSRFState := base64.StdEncoding.EncodeToString(b)
	return &AuthenticationURL{
		url:   a.config.AuthCodeURL(CSRFState),
		state: CSRFState,
	}, nil
}

func (a *Authenticator) Verify(ctx context.Context, code string) (*oidc.IDToken, error) {
	token, err := a.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenNotFound, err)
	}

	rawIDToken, exist := token.Extra("id_token").(string)
	if !exist {
		return nil, fmt.Errorf("%w: %v", ErrIDTokenNotFound, err)
	}

	cfg := &oidc.Config{ClientID: "qHcV8N1iSntNMbZGxG6wP38sofmEK9aB"}

	idToken, err := a.provider.Verifier(cfg).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
	}

	return idToken, nil
}
