package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/mateoferrari97/Users-API/cmd/app/auth"
	"github.com/mateoferrari97/Users-API/cmd/app/jwt"
	"strings"
)

var (
	ErrEntityNotFound = errors.New("service: entity not found")
	ErrVerification   = errors.New("service: code verification failed")
	ErrTokenCreation  = errors.New("service: token creation failed")
	ErrTokenParse     = errors.New("service: token parse failed")
)

type Service struct {
	authenticator *auth.Authenticator
	token         *jwt.JWT
}

func NewService(authenticator *auth.Authenticator, token *jwt.JWT) *Service {
	return &Service{
		authenticator: authenticator,
		token:         token,
	}
}

func (s *Service) CreateAuthenticationURL() (*auth.AuthenticationURL, error) {
	return s.authenticator.CreateAuthenticationURL()
}

func (s *Service) Verify(ctx context.Context, code string) (string, error) {
	idToken, err := s.authenticator.Verify(ctx, code)
	if err != nil {
		switch err {
		case auth.ErrTokenNotFound, auth.ErrIDTokenNotFound:
			return "", ErrEntityNotFound
		case auth.ErrAuthenticationFailed:
			return "", ErrVerification
		}

		return "", err
	}

	token, err := s.token.Create(idToken, idToken.Subject)
	if err != nil {
		switch err {
		case jwt.ErrSubjectNotFound, jwt.ErrUnsupportedProvider:
			return "", ErrTokenCreation
		}

		return "", err
	}

	return token, nil
}

func (s *Service) ParseToken(token string) (jwt.Claims, error) {
	sToken := strings.Split(token, " ")
	if len(sToken) != 2 {
		return nil, fmt.Errorf("%w: invalid token length", ErrTokenParse)
	}

	claims, err := s.token.Claims(sToken[1])
	if err != nil {
		switch err {
		case jwt.ErrTokenMalformed, jwt.ErrTokenTime:
			return nil, ErrTokenParse
		}

		return nil, err
	}

	return claims, nil
}
