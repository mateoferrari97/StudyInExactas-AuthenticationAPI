package main

import (
	"github.com/mateoferrari97/Users-API/cmd/app/service/auth"
	"os"

	"github.com/mateoferrari97/Kit/web/server"
	"github.com/mateoferrari97/Users-API/cmd/app"
	"github.com/mateoferrari97/Users-API/cmd/app/service"
	"github.com/mateoferrari97/Users-API/cmd/app/service/jwt"

	"github.com/gorilla/sessions"
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

	sv := server.NewServer()
	token := jwt.NewJWT(signingKey)
	service_ := service.NewService(authenticator, token)
	storage := sessions.NewCookieStore([]byte(storeKey))

	handler := app.NewHandler(sv, service_, storage)
	handler.Login()
	handler.LoginCallback()
	handler.Logout()
	handler.Me() // server.ValidateJWT(signingKey)

	return sv.Run(port)
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
		result = ":8080"
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
	result := "qHcV8N1iSntNMbZGxG6wP38sofmEK9aB"
	if env == "production" {
		result = os.Getenv("AUTH0_CLIENT_ID")
	}

	return result
}

func getClientSecret(env string) string {
	result := "YoEyXYMjjXf82CjoAYzOaNqJwFyDz5162kqBSuSI9kzqAEPwcBkjFM31s_JAZ8JG"
	if env == "production" {
		result = os.Getenv("AUTH0_CLIENT_SECRET")
	}

	return result
}
