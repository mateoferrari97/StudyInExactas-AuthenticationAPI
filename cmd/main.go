package main

import (
	"errors"
	"github.com/mateoferrari97/Users-API/cmd/app"
	"github.com/mateoferrari97/Users-API/cmd/app/auth"
	"github.com/mateoferrari97/Users-API/cmd/app/store"
	"github.com/mateoferrari97/Users-API/internal/web"
	"os"
)

const (
	_defaultPort = "8080"
)

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	env := os.Getenv("ENVIRONMENT")
	authenticator, err := auth.NewAuthenticator(env)
	if err != nil {
		return err
	}

	port := _defaultPort
	if env == "production" {
		port = os.Getenv("PORT")
		if port == "" {
			return errors.New("empty port, need to configure it")
		}
	}

	server := web.NewServer(web.WithPort(port))
	service := app.NewService(authenticator)

	handler := app.NewHandler(server, service, store.NewFileSystemStore())
	handler.Login()
	handler.LoginCallback()
	handler.Me()

	return server.Run()
}
