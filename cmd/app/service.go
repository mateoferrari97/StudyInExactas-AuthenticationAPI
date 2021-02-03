package app

import (
	"context"
	"github.com/mateoferrari97/Users-API/cmd/app/auth"
	"github.com/mateoferrari97/Users-API/cmd/app/token"
)

type Service struct {
	authenticator *auth.Authenticator
	token         *token.Token
}

func NewService(authenticator *auth.Authenticator, token *token.Token) *Service {
	return &Service{
		authenticator: authenticator,
		token:         token,
	}
}

func (s *Service) CreateAuthenticationURL() (*auth.AuthenticationURL, error) {
	return s.authenticator.CreateAuthenticationURL()
}

func (s *Service) VerifyAuthentication(ctx context.Context, code string) (string, error) {
	idToken, err := s.authenticator.Verify(ctx, code)
	if err != nil {
		return "", err
	}

	return s.token.Create(idToken.Claims, idToken.Subject)
}

func (s *Service) ParseToken(signedToken string) (token.Claims, error) {
	return s.token.Claims(signedToken)
}
