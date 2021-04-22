package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mateoferrari97/Users-API/cmd/app/service/auth"
	"github.com/mateoferrari97/Users-API/cmd/app/service/jwt"
	"strings"
)

var (
	ErrNotFound     = errors.New("service: resource not found")
	ErrVerification = errors.New("service: could not verify resource")
	ErrCreation     = errors.New("service: could not create resource")
	ErrParse        = errors.New("service: could not parse resource")
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

func (s *Service) CreateAuthentication() (url, state string, err error) {
	return s.authenticator.CreateAuthenticationURL()
}

func (s *Service) VerifyAuthentication(ctx context.Context, code string) (string, error) {
	idToken, err := s.authenticator.VerifyAuthentication(ctx, code)
	if err != nil {
		switch err {
		case auth.ErrTokenNotFound, auth.ErrIDTokenNotFound:
			return "", ErrNotFound
		case auth.ErrAuthenticationFailed:
			return "", ErrVerification
		}

		return "", err
	}

	token, err := s.token.Create(idToken, idToken.Subject)
	if err != nil {
		if errors.Is(err, jwt.ErrSubjectNotFound) || errors.Is(err, jwt.ErrUnsupportedProvider) {
			return "", ErrCreation
		}

		return "", err
	}

	return token, nil
}

func (s *Service) GetMyInformation(token string) ([]byte, error) {
	sToken := strings.Split(token, " ")
	if len(sToken) != 2 {
		return nil, fmt.Errorf("%w: invalid token length", ErrParse)
	}

	claims, err := s.token.Claims(sToken[1])
	if err != nil {
		if errors.Is(err, jwt.ErrTokenMalformed) || errors.Is(err, jwt.ErrTokenTime) {
			return nil, ErrCreation
		}

		return nil, err
	}

	b, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("could not marshal claims: %v", err)
	}

	return b, nil
}
