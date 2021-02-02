package main

import (
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
	authenticator, err := auth.NewAuthenticator()
	if err != nil {
		return err
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = _defaultPort
	}

	server := web.NewServer(web.WithPort(":" + port))
	service := app.NewService(authenticator)

	handler := app.NewHandler(server, service, store.NewFileSystemStore())
	handler.Login()
	handler.LoginCallback()
	handler.Me()

	return server.Run()
}
