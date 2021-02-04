package app

import (
	"encoding/json"
	"github.com/gorilla/sessions"
	"github.com/mateoferrari97/Users-API/internal/web"
	"net/http"
	"strings"
)

type Store interface {
	Get(r *http.Request, name string) (*sessions.Session, error)
	Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error
}

type Handler struct {
	service *Service
	server  *web.Server
	store   Store
}

func NewHandler(server *web.Server, service *Service, store Store) *Handler {
	return &Handler{
		service: service,
		server:  server,
		store:   store,
	}
}

func (h *Handler) Login(mws ...web.Middleware) {
	wrapH := func(w http.ResponseWriter, r *http.Request) error {
		authenticationURL, err := h.service.CreateAuthenticationURL()
		if err != nil {
			return err
		}

		session, err := h.store.Get(r, "auth-session")
		if err != nil {
			return err
		}

		session.Values["state"] = authenticationURL.State()
		if err = session.Save(r, w); err != nil {
			return err
		}

		http.Redirect(w, r, authenticationURL.String(), http.StatusTemporaryRedirect)

		return nil
	}

	h.server.Wrap(http.MethodGet, "/login", wrapH, mws...)
}

func (h *Handler) LoginCallback(mws ...web.Middleware) {
	wrapH := func(w http.ResponseWriter, r *http.Request) error {
		session, err := h.store.Get(r, "auth-session")
		if err != nil {
			return err
		}

		if r.URL.Query().Get("state") != session.Values["state"] {
			return web.NewError(http.StatusForbidden, "invalid state parameter")
		}

		session.Options.MaxAge = -1
		if err := session.Save(r, w); err != nil {
			return err
		}

		if r.URL.Query().Get("code") == "" {
			return web.NewError(http.StatusForbidden, "invalid code parameter")
		}

		token, err := h.service.VerifyAuthentication(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			return err
		}

		c := &http.Cookie{
			Name:     "token",
			Value:    token,
			HttpOnly: true,
			Path:     "/",
		}

		http.SetCookie(w, c)

		return nil
	}

	h.server.Wrap(http.MethodGet, "/login/callback", wrapH, mws...)
}

func (h *Handler) Me(mws ...web.Middleware) {
	wrapH := func(w http.ResponseWriter, r *http.Request) error {
		token := r.Header.Get("Authorization")

		signedToken := strings.Split(token, " ")
		if len(signedToken) != 2 {
			return web.NewError(http.StatusForbidden, "invalid token length")
		}

		parsedToken, err := h.service.ParseToken(signedToken[0])
		if err != nil {
			return err
		}

		return json.NewEncoder(w).Encode(parsedToken)
	}

	h.server.Wrap(http.MethodGet, "/me", wrapH, mws...)
}
