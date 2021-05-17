package jwt

import (
	"errors"
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

var (
	ErrNotFound            = errors.New("jwt: resource not found")
	ErrUnsupportedProvider = errors.New("jwt: unsupported provider")
	ErrMalformedToken      = errors.New("jwt: malformed token")
	ErrExpiredToken        = errors.New("jwt: token has expired or is not valid yet")
)

type UnmarshalClaims interface {
	Claims(v interface{}) error
}

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

func (t *JWT) Create(v UnmarshalClaims, subject string) (string, error) {
	if subject == "" {
		return "", ErrNotFound
	}

	if !strings.Contains(subject, "google-oauth2") && !strings.Contains(subject, "windowslive") {
		return "", fmt.Errorf("%w: got: (%s), want: (google-oauth2 and windowslive)", ErrUnsupportedProvider, subject)
	}

	return t.create(v)
}

func (t *JWT) create(v UnmarshalClaims) (string, error) {
	customClaims, err := extractClaims(v)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(t.signingMethod, customClaims)

	signedToken, err := token.SignedString([]byte(t.signingKey))
	if err != nil {
		return "", fmt.Errorf("could not sign token: %v", err)
	}

	return signedToken, nil
}

type Claims interface {
	jwt.Claims
}

type CClaims struct {
	Metadata MetaData `json:"metadata"`
	jwt.StandardClaims
}

type MetaData struct {
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

func extractClaims(v UnmarshalClaims) (CClaims, error) {
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
		return CClaims{}, fmt.Errorf("could not fetch claims: %v", err)
	}

	return CClaims{
		Metadata: MetaData{
			Name:      claims.Name,
			Email:     claims.Email,
			AvatarURL: claims.Picture,
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
		var hErr *jwt.ValidationError
		if errors.As(err, &hErr) {
			if hErr.Errors == jwt.ValidationErrorExpired || hErr.Errors == jwt.ValidationErrorNotValidYet {
				return nil, ErrExpiredToken
			}
		}

		return nil, fmt.Errorf("could not handle jwt: %w: %v", ErrMalformedToken, err)
	}

	return token.Claims, nil
}
