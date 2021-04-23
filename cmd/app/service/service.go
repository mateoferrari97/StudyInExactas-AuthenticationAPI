package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"strings"

	"github.com/mateoferrari97/Users-API/cmd/app/service/auth"
	"github.com/mateoferrari97/Users-API/cmd/app/service/jwt"
)

var (
	ErrNotFound     = errors.New("service: resource not found")
	ErrVerification = errors.New("service: could not verify resource")
	ErrCreation     = errors.New("service: could not create resource")
	ErrParse        = errors.New("service: could not parse resource")
)

type Authenticator interface {
	CreateAuthentication() (uri, state string, err error)
	VerifyAuthentication(ctx context.Context, code string) (idToken *oidc.IDToken, err error)
}

type JWT interface {
	Create(v jwt.UnmarshalClaims, subject string) (string, error)
	Claims(signedToken string) (jwt.Claims, error)
}

type Service struct {
	authenticator Authenticator
	jwt         JWT
}

func NewService(authenticator Authenticator, jwt JWT) *Service {
	return &Service{
		authenticator: authenticator,
		jwt:         jwt,
	}
}

func (s *Service) CreateAuthentication() (url, state string, err error) {
	return s.authenticator.CreateAuthentication()
}

func (s *Service) VerifyAuthentication(ctx context.Context, code string) (string, error) {
	idToken, err := s.authenticator.VerifyAuthentication(ctx, code)
	if err != nil {
		switch err {
		case auth.ErrNotFound:
			return "", fmt.Errorf("could not verify authentication: %w", ErrNotFound)
		case auth.ErrAuthenticationFailed:
			return "", fmt.Errorf("could not verify authentication: %w", ErrVerification)
		}

		return "", fmt.Errorf("could not verify authentication: %v", err)
	}

	token, err := s.jwt.Create(idToken, idToken.Subject)
	if err != nil {
		if errors.Is(err, jwt.ErrNotFound) || errors.Is(err, jwt.ErrUnsupportedProvider) {
			return "", fmt.Errorf("could not create token: %w", ErrCreation)
		}

		return "", fmt.Errorf("could not create token: %v", err)
	}

	return token, nil
}

func (s *Service) GetMyInformation(token string) ([]byte, error) {
	sToken := strings.Split(token, " ")
	if len(sToken) != 2 {
		return nil, fmt.Errorf("invalid token length: %w", ErrParse)
	}

	claims, err := s.jwt.Claims(sToken[1])
	if err != nil {
		if errors.Is(err, jwt.ErrMalformedToken) || errors.Is(err, jwt.ErrExpiredToken) {
			return nil, fmt.Errorf("could not fetch claims: %v", ErrCreation)
		}

		return nil, err
	}

	b, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("could not marshal claims: %v", err)
	}

	return b, nil
}
