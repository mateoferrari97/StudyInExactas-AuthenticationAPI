package main

import (
	"github.com/gorilla/sessions"
	"github.com/mateoferrari97/Users-API/cmd/app"
	"github.com/mateoferrari97/Users-API/cmd/app/auth"
	"github.com/mateoferrari97/Users-API/cmd/app/jwt"
	"github.com/mateoferrari97/Users-API/internal/web"
	"os"
)

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	var (
		env          = getEnv()
		port         = getPort()
		signingKey   = getJWTSigningKey()
		storeKey     = getStoreKey()
		baseURL      = getBaseURL(env)
		clientID     = getClientID(env)
		clientSecret = getClientSecret(env)
	)

	authenticator, err := auth.NewAuthenticator(baseURL, clientID, clientSecret)
	if err != nil {
		return err
	}

	token := jwt.NewJWT(signingKey)
	service := app.NewService(authenticator, token)
	server := web.NewServer(web.WithPort(port))
	store := sessions.NewCookieStore([]byte(storeKey))

	handler := app.NewHandler(server, service, store)
	handler.Login()
	handler.LoginCallback()
	handler.Logout(web.ValidateJWT(signingKey))
	handler.Me(web.ValidateJWT(signingKey))

	return server.Run()
}

func getEnv() string {
	result := os.Getenv("ENVIRONMENT")
	if result == "" {
		result = "staging"
	}

	return result
}

func getJWTSigningKey() string {
	result := os.Getenv("JWT_SIGNING_KEY")
	if result == "" {
		result = "JWT_SIGNING_KEY"
	}

	return result
}

func getPort() string {
	result := os.Getenv("PORT")
	if result == "" {
		result = "8080"
	}

	return result
}

func getStoreKey() string {
	result := os.Getenv("STORE_KEY")
	if result == "" {
		result = "STORE_KEY"
	}

	return result
}

func getBaseURL(env string) string {
	result := "http://localhost:8080"
	if env == "production" {
		result = os.Getenv("BASE_URL")
	}

	return result
}

func getClientID(env string) string {
	result := "clientID"
	if env == "production" {
		result = os.Getenv("AUTH0_CLIENT_ID")
	}

	return result
}

func getClientSecret(env string) string {
	result := "clientSecret"
	if env == "production" {
		result = os.Getenv("AUTH0_CLIENT_SECRET")
	}

	return result
}
