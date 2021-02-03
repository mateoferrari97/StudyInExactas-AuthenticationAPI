package main

import (
	"github.com/mateoferrari97/Users-API/cmd/app"
	"github.com/mateoferrari97/Users-API/cmd/app/auth"
	"github.com/mateoferrari97/Users-API/cmd/app/store"
	"github.com/mateoferrari97/Users-API/cmd/app/token"
	"github.com/mateoferrari97/Users-API/internal/web"
	"os"
)

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	authenticatorService, err := auth.NewAuthenticator(os.Getenv("ENVIRONMENT"))
	if err != nil {
		return err
	}

	tokenService, err := token.NewToken("SIGNINGKEY")
	if err != nil {
		return err
	}

	mainService := app.NewService(authenticatorService, tokenService)

	server := web.NewServer(web.WithPort(os.Getenv("PORT")))

	handler := app.NewHandler(server, mainService, store.NewFileSystemStore())
	handler.Login()
	handler.LoginCallback()
	handler.Me()

	return server.Run()
}
