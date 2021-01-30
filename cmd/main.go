package main

import (
	"github.com/mateoferrari97/Users-API/cmd/app"
	"github.com/mateoferrari97/Users-API/cmd/app/auth"
	"github.com/mateoferrari97/Users-API/cmd/app/store"
	"github.com/mateoferrari97/Users-API/internal/web"
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

	server := web.NewServer()
	service := app.NewService(authenticator)

	handler := app.NewHandler(server, service, store.NewFileSystemStore())
	handler.Login()
	handler.LoginCallback()
	handler.Me()

	return server.Run()
}
