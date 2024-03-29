package main

import (
	"os"

	"github.com/mateoferrari97/AnitiMonono-AuthenticationAPI/cmd/server/internal"
	"github.com/mateoferrari97/AnitiMonono-AuthenticationAPI/cmd/server/internal/authentication"
	"github.com/mateoferrari97/AnitiMonono-AuthenticationAPI/cmd/server/internal/authentication/auth"
	"github.com/mateoferrari97/AnitiMonono-AuthenticationAPI/cmd/server/internal/authentication/jwt"
	"github.com/mateoferrari97/Kit/web/server"

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
		host         = getHost(env)
		clientID     = getClientID(env)
		clientSecret = getClientSecret(env)
	)

	authenticator, err := auth.NewAuthenticator(host, clientID, clientSecret)
	if err != nil {
		return err
	}

	sv := server.NewServer()
	token := jwt.NewJWT(signingKey)
	service_ := authentication.NewService(authenticator, token)
	storage := sessions.NewCookieStore([]byte(storeKey))

	handler := internal.NewHandler(sv, service_, storage)
	handler.Login()
	handler.LoginCallback()
	handler.Logout() // server.ValidateJWT(signingKey)
	handler.Me()     // server.ValidateJWT(signingKey)

	return sv.Run(port)
}

func getEnv() string {
	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "staging"
	}

	return env
}

func getJWTSigningKey() string {
	signingKey := os.Getenv("JWT_SIGNING_KEY")
	if signingKey == "" {
		signingKey = "JWT_SIGNING_KEY"
	}

	return signingKey
}

func getPort() string {
	port := os.Getenv("PORT")
	if port == "" {
		return ":8080"
	}

	return ":" + port
}

func getHost(env string) string {
	host := "http://localhost:8080"
	if env == "production" {
		host = os.Getenv("BASE_URL")
	}

	return host
}

func getStoreKey() string {
	storeKey := os.Getenv("STORE_KEY")
	if storeKey == "" {
		storeKey = "STORE_KEY"
	}

	return storeKey
}

func getClientID(env string) string {
	clientID := "qHcV8N1iSntNMbZGxG6wP38sofmEK9aB"
	if env == "production" {
		clientID = os.Getenv("AUTH0_CLIENT_ID")
	}

	return clientID
}

func getClientSecret(env string) string {
	clientSecret := "YoEyXYMjjXf82CjoAYzOaNqJwFyDz5162kqBSuSI9kzqAEPwcBkjFM31s_JAZ8JG"
	if env == "production" {
		clientSecret = os.Getenv("AUTH0_CLIENT_SECRET")
	}

	return clientSecret
}
