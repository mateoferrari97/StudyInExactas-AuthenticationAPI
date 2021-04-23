package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrNotFound             = errors.New("auth: resource not found")
	ErrAuthenticationFailed = errors.New("auth: authentication failed")
)

type Authenticator struct {
	provider     *oidc.Provider
	config       oauth2.Config
	clientID     string
	clientSecret string
}

func NewAuthenticator(baseURL string, clientID string, clientSecret string) (*Authenticator, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "https://food4everyone.us.auth0.com/")
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	conf := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  fmt.Sprintf("%s/login/callback", baseURL),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &Authenticator{
		provider:     provider,
		config:       conf,
		clientID:     clientID,
		clientSecret: clientSecret,
	}, nil
}

type AuthenticationURL struct {
	state string
	url   string
}

func (a *Authenticator) CreateAuthenticationURL() (url, state string, err error) {
	b := make([]byte, 32)
	_, err = rand.Read(b)
	if err != nil {
		return "", "", err
	}

	CSRFState := base64.StdEncoding.EncodeToString(b)
	return a.config.AuthCodeURL(CSRFState), CSRFState, nil
}

func (a *Authenticator) VerifyAuthentication(ctx context.Context, code string) (*oidc.IDToken, error) {
	token, err := a.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("could not exchange code %w: %v", ErrNotFound, err)
	}

	rawIDToken, exist := token.Extra("id_token").(string)
	if !exist {
		return nil, fmt.Errorf("could not find id_token %w: %v", ErrNotFound, err)
	}

	cfg := &oidc.Config{ClientID: a.clientID}

	idToken, err := a.provider.Verifier(cfg).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify token %w: %v", ErrAuthenticationFailed, err)
	}

	return idToken, nil
}
