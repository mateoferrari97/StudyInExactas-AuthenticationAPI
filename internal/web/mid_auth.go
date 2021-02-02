package web

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/mateoferrari97/Kit/web"
	"net/http"
	"strings"
)

func ValidateJWT(secret string) Middleware {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("Authorization")
			if token == "" {
				_ = web.RespondJSON(w, web.NewError("token is required", http.StatusForbidden), http.StatusForbidden)
				return
			}

			sToken := strings.Split(token, " ")
			if len(sToken) != 2 {
				_ = web.RespondJSON(w, web.NewError("invalid token length", http.StatusForbidden), http.StatusForbidden)
				return
			}

			if sToken[0] != "Bearer" {
				_ = web.RespondJSON(w, web.NewError("invalid token type", http.StatusForbidden), http.StatusForbidden)
				return
			}

			if sToken[1] == "" {
				_ = web.RespondJSON(w, web.NewError("token value is required", http.StatusForbidden), http.StatusForbidden)
				return
			}

			if err := validateToken(sToken[1], secret); err != nil {
				_ = web.RespondJSON(w, web.NewError(err.Error(), http.StatusForbidden), http.StatusForbidden)
				return
			}

			h(w, r)
		}
	}
}

func validateToken(t string, secret string) error {
	if _, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) { return []byte(secret), nil }); err != nil {
		var e *jwt.ValidationError
		if errors.As(err, &e) {
			switch e.Errors {
			case jwt.ValidationErrorMalformed:
				return errors.New("malformed token")
			case jwt.ValidationErrorExpired, jwt.ValidationErrorNotValidYet:
				return errors.New("token has expired or is not valid yet")
			default:
				return e
			}
		}

		return fmt.Errorf("couldn't handle this token: %v", err)
	}

	return nil
}
