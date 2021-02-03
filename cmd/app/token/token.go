package token

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"strings"
)

var (
	ErrSubjectNotFound      = errors.New("token: subject not found")
	ErrSubjectInvalidLength = errors.New("token: subject invalid length")
	ErrUnsupportedProvider  = errors.New("token: unsupported provider")
	ErrTokenMalformed       = errors.New("token: malformed token")
	ErrTokenTime            = errors.New("token: token has expired or is not valid yet")
)

type Token struct {
	signingKey    string
	signingMethod jwt.SigningMethod
}

type f func(v interface{}) error

func NewToken(signingKey string) (*Token, error) {
	return &Token{
		signingKey:    signingKey,
		signingMethod: jwt.SigningMethodHS256,
	}, nil
}

type Claims interface {
	Valid() error
}

type CClaims struct {
	Metadata MetaData `json:"metadata"`
	jwt.StandardClaims
}

type MetaData struct {
	Name          string `json:"name"`
	Email         string `json:"email"`
	AvatarURL     string `json:"avatar_url"`
	OAuthProvider string `json:"o_auth_provider"`
}

func (t *Token) Create(f func(v interface{}) error, subject string) (string, error) {
	if subject == "" {
		return "", ErrSubjectNotFound
	}

	if strings.Contains(subject, "google-oauth2") || strings.Contains(subject, "windowslive") {
		return "", fmt.Errorf("%w: got: (%s), want: (google-oauth2 and windowslive)", ErrUnsupportedProvider, subject)
	}

	return t.create(f, subject)
}

func (t *Token) create(f func(v interface{}) error, subject string) (string, error) {
	customClaims, err := extractClaims(f, subject)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(t.signingMethod, customClaims)

	signedToken, err := token.SignedString(t.signingKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func extractClaims(f func(v interface{}) error, subject string) (CClaims, error) {
	var claims struct {
		Aud     string `json:"aud"`
		Exp     int64  `json:"exp"`
		Iat     int64  `json:"iat"`
		Iss     string `json:"iss"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture string `json:"picture"`
		Sub     string `json:"sub"`
	}

	if err := f(&claims); err != nil {
		return CClaims{}, err
	}

	return CClaims{
		Metadata: MetaData{
			Name:          claims.Name,
			Email:         claims.Email,
			AvatarURL:     claims.Picture,
			OAuthProvider: subject,
		},
		StandardClaims: jwt.StandardClaims{
			Audience:  claims.Aud,
			ExpiresAt: claims.Exp,
			IssuedAt:  claims.Iat,
			Issuer:    claims.Iss,
			Subject:   claims.Sub,
		},
	}, nil
}

func (t *Token) Claims(signedToken string) (Claims, error) {
	token, err := jwt.Parse(signedToken, func(token *jwt.Token) (interface{}, error) { return []byte(t.signingKey), nil })
	if err != nil {
		var e *jwt.ValidationError
		if errors.As(err, &e) {
			switch e.Errors {
			case jwt.ValidationErrorMalformed:
				return nil, ErrTokenMalformed
			case jwt.ValidationErrorExpired, jwt.ValidationErrorNotValidYet:
				return nil, ErrTokenTime
			default:
				return nil, e
			}
		}

		return nil, fmt.Errorf("couldn't handle this token: %v", err)
	}

	return token.Claims, nil
}
