package app

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/mateoferrari97/Users-API/internal/web"
	"net/http"
	"strings"
)

type Handler struct {
	server  *web.Server
	service *Service
	store   sessions.Store
}

func NewHandler(server *web.Server, service *Service, store sessions.Store) *Handler {
	return &Handler{
		server:  server,
		service: service,
		store:   store,
	}
}

func (h *Handler) Login() {
	wrapH := func(w http.ResponseWriter, r *http.Request) error {
		state, authCodeURL, err := h.service.CreateCSRFState()
		if err != nil {
			return err
		}

		session, err := h.store.Get(r, "auth-session")
		if err != nil {
			return err
		}

		session.Values["state"] = state
		if err = session.Save(r, w); err != nil {
			return err
		}

		http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
		return nil
	}

	h.server.Wrap(http.MethodGet, "/login", wrapH)
}

func (h *Handler) LoginCallback() {
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

		idToken, err := h.service.Authenticate(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			return err
		}

		token, err := h.service.CreateJWT(idToken)
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

	h.server.Wrap(http.MethodGet, "/login/callback", wrapH)
}

func (h *Handler) Me() {
	wrapH := func(w http.ResponseWriter, r *http.Request) error {
		t := r.Header.Get("Authorization")

		sToken := strings.Split(t, " ")
		token, err := jwt.Parse(sToken[1], func(token *jwt.Token) (interface{}, error) { return []byte("foooood"), nil })
		if err != nil {
			return err
		}

		return json.NewEncoder(w).Encode(token.Claims)
	}

	h.server.Wrap(http.MethodGet, "/me", wrapH, web.ValidateJWT("foooood"))
}
