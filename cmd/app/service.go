package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"github.com/coreos/go-oidc/oidc"
	"github.com/dgrijalva/jwt-go"
	"github.com/mateoferrari97/Users-API/cmd/app/auth"
	"github.com/mateoferrari97/Users-API/internal/web"
	"net/http"
	"strings"
)

type Service struct {
	Authenticator *auth.Authenticator
}

func NewService(authenticator *auth.Authenticator) *Service {
	return &Service{Authenticator: authenticator}
}

func (s *Service) CreateCSRFState() (state string, authCodeURL string, err error) {
	b := make([]byte, 32)
	_, err = rand.Read(b)
	if err != nil {
		return "", "", err
	}

	state = base64.StdEncoding.EncodeToString(b)

	return state, s.Authenticator.Config.AuthCodeURL(state), nil
}

func (s *Service) Authenticate(ctx context.Context, code string) (*oidc.IDToken, error) {
	token, err := s.Authenticator.Config.Exchange(ctx, code)
	if err != nil {
		return nil, web.NewErrorf(http.StatusForbidden, "no token found: %v", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, web.NewError(http.StatusInternalServerError, "no id_token field in oauth2 token")
	}

	cfg := &oidc.Config{ClientID: "qHcV8N1iSntNMbZGxG6wP38sofmEK9aB"}

	idToken, err := s.Authenticator.Provider.Verifier(cfg).Verify(context.TODO(), rawIDToken)
	if err != nil {
		return nil, web.NewErrorf(http.StatusForbidden, "failed to verify id token: %v", err)
	}

	return idToken, nil
}

type metaData struct {
	Name            string `json:"name"`
	Email           string `json:"email"`
	AvatarURL       string `json:"avatar_url"`
	OAuthProvider   string `json:"o_auth_provider"`
	OAuthProviderID string `json:"o_auth_provider_id"`
}

type customClaims struct {
	Metadata metaData `json:"metadata"`
	jwt.StandardClaims
}

func (s *Service) CreateJWT(idToken *oidc.IDToken) (string, error) {
	mySigningKey := []byte("foooood")

	subject := idToken.Subject
	if subject == "" {
		return "", web.NewError(http.StatusInternalServerError, "subject is empty")
	}

	providerAndUserProviderID := strings.Split(subject, "|")
	if len(providerAndUserProviderID) != 2 {
		return "", web.NewError(http.StatusInternalServerError, "invalid subject length")
	}

	var cc customClaims
	switch providerAndUserProviderID[0] {
	case "google-oauth2":
		result, err := googleClaimsParser(idToken)
		if err != nil {
			return "", err
		}

		cc = result
	case "windowslive":
		result, err := windowsClaimsParser(idToken)
		if err != nil {
			return "", err
		}

		cc = result
	default:
		return "", web.NewErrorf(http.StatusInternalServerError, "invalid provider: %s", providerAndUserProviderID[0])
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cc)
	ss, err := token.SignedString(mySigningKey)
	if err != nil {
		return "", err
	}

	return ss, nil
}

func googleClaimsParser(idToken *oidc.IDToken) (customClaims, error) {
	var googleClaims struct {
		Aud     string `json:"aud"`
		Exp     int64  `json:"exp"`
		Iat     int64  `json:"iat"`
		Iss     string `json:"iss"`
		Locale  string `json:"locale"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture string `json:"picture"`
		Sub     string `json:"sub"`
	}

	if err := idToken.Claims(&googleClaims); err != nil {
		return customClaims{}, nil
	}

	subject := strings.Split(googleClaims.Sub, "|")

	return customClaims{
		Metadata: metaData{
			Name:            googleClaims.Name,
			Email:           googleClaims.Email,
			AvatarURL:       googleClaims.Picture,
			OAuthProvider:   subject[0],
			OAuthProviderID: subject[1],
		},
		StandardClaims: jwt.StandardClaims{
			Audience:  googleClaims.Aud,
			ExpiresAt: googleClaims.Exp,
			IssuedAt:  googleClaims.Iat,
			Issuer:    googleClaims.Iss,
			Subject:   googleClaims.Sub,
		},
	}, nil
}

func windowsClaimsParser(idToken *oidc.IDToken) (customClaims, error) {
	var windowsClaims struct {
		Aud     string `json:"aud"`
		Exp     int64  `json:"exp"`
		Iat     int64  `json:"iat"`
		Iss     string `json:"iss"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture string `json:"picture"`
		Sub     string `json:"sub"`
	}

	if err := idToken.Claims(&windowsClaims); err != nil {
		return customClaims{}, nil
	}

	subject := strings.Split(windowsClaims.Sub, "|")

	return customClaims{
		Metadata: metaData{
			Name:            windowsClaims.Name,
			Email:           windowsClaims.Email,
			AvatarURL:       windowsClaims.Picture,
			OAuthProvider:   subject[0],
			OAuthProviderID: subject[1],
		},
		StandardClaims: jwt.StandardClaims{
			Audience:  windowsClaims.Aud,
			ExpiresAt: windowsClaims.Exp,
			IssuedAt:  windowsClaims.Iat,
			Issuer:    windowsClaims.Iss,
			Subject:   windowsClaims.Sub,
		},
	}, nil
}
