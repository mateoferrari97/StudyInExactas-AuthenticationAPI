package jwt

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"strings"
)

var (
	ErrSubjectNotFound     = errors.New("jwt: subject not found")
	ErrUnsupportedProvider = errors.New("jwt: unsupported provider")
	ErrTokenMalformed      = errors.New("jwt: malformed token")
	ErrTokenTime           = errors.New("jwt: token has expired or is not valid yet")
)

type JWT struct {
	signingKey    string
	signingMethod jwt.SigningMethod
}

func NewJWT(signingKey string) *JWT {
	return &JWT{
		signingKey:    signingKey,
		signingMethod: jwt.SigningMethodHS256,
	}
}

type UnmarshalClaims interface {
	Claims(v interface{}) error
}

type Claims interface {
	jwt.Claims
}

type CClaims struct {
	Metadata MetaData `json:"metadata"`
	jwt.StandardClaims
}

type MetaData struct {
	Name          string `json:"name"`
	Email         string `json:"email"`
	AvatarURL     string `json:"avatar_url"`
}

func (t *JWT) Create(v UnmarshalClaims, subject string) (string, error) {
	if subject == "" {
		return "", ErrSubjectNotFound
	}

	if !strings.Contains(subject, "google-oauth2") && !strings.Contains(subject, "windowslive") {
		return "", fmt.Errorf("%w: got: (%s), want: (google-oauth2 and windowslive)", ErrUnsupportedProvider, subject)
	}

	return t.create(v, subject)
}

func (t *JWT) create(v UnmarshalClaims, subject string) (string, error) {
	customClaims, err := extractClaims(v, subject)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(t.signingMethod, customClaims)

	signedToken, err := token.SignedString([]byte(t.signingKey))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func extractClaims(v UnmarshalClaims, subject string) (CClaims, error) {
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

	if err := v.Claims(&claims); err != nil {
		return CClaims{}, err
	}

	return CClaims{
		Metadata: MetaData{
			Name:          claims.Name,
			Email:         claims.Email,
			AvatarURL:     claims.Picture,
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

func (t *JWT) Claims(signedToken string) (Claims, error) {
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

		return nil, fmt.Errorf("could not handle this jwt: %v", err)
	}

	return token.Claims, nil
}
