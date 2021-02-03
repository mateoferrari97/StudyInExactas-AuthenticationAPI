package token

import (
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
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

func (t *Token) Create(idToken *oidc.IDToken) (string, error) {
	if idToken.Subject == "" {
		return "", ErrSubjectNotFound
	}

	subject := strings.Split(idToken.Subject, "|")
	if len(subject) != 2 {
		return "", ErrSubjectInvalidLength
	}

	if subject[0] == "" {
		return "", ErrSubjectNotFound
	}

	if subject[0] != "google-oauth2" && subject[0] != "windowslive" {
		return "", fmt.Errorf("%w: got: (%s), want: (google-oauth2 and windowslive)", ErrUnsupportedProvider, subject)
	}

	return t.create(idToken, subject[0])
}

func (t *Token) create(idToken *oidc.IDToken, subject string) (string, error) {
	customClaims, err := extractClaims(idToken, subject)
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

func extractClaims(idToken *oidc.IDToken, subject string) (CClaims, error) {
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

	if err := idToken.Claims(&claims); err != nil {
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
