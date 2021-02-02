package auth

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Authenticator struct {
	Provider *oidc.Provider
	Config   oauth2.Config
	Ctx      context.Context
}

func NewAuthenticator() (*Authenticator, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "https://food4everyone.us.auth0.com/")
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	conf := oauth2.Config{
		ClientID:     "qHcV8N1iSntNMbZGxG6wP38sofmEK9aB",
		ClientSecret: "YoEyXYMjjXf82CjoAYzOaNqJwFyDz5162kqBSuSI9kzqAEPwcBkjFM31s_JAZ8JG",
		RedirectURL:  "http://localhost:8080/login/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &Authenticator{
		Provider: provider,
		Config:   conf,
		Ctx:      ctx,
	}, nil
}
