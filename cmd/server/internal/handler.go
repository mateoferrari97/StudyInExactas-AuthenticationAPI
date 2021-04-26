package internal

import (
	"context"
	"errors"
	"net/http"

	"github.com/mateoferrari97/AnitiMonono-AuthenticationAPI/cmd/server/internal/service"
	"github.com/mateoferrari97/Kit/web/server"

	"github.com/gorilla/sessions"
)

type Wrapper interface {
	Wrap(method, pattern string, f server.HandlerFunc, mws ...server.Middleware)
}

type Service interface {
	CreateAuthentication() (url, state string, err error)
	VerifyAuthentication(ctx context.Context, code string) (string, error)
	GetMyInformation(token string) ([]byte, error)
}

type Storage interface {
	Get(r *http.Request, name string) (*sessions.Session, error)
	Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error
}

type Handler struct {
	service Service
	wrapper Wrapper
	storage Storage
}

func NewHandler(wrapper Wrapper, service Service, storage Storage) *Handler {
	return &Handler{
		service: service,
		wrapper: wrapper,
		storage: storage,
	}
}

func (h *Handler) Login(mws ...server.Middleware) {
	wrapH := func(w http.ResponseWriter, r *http.Request) error {
		uri, state, err := h.service.CreateAuthentication()
		if err != nil {
			return err
		}

		session, err := h.storage.Get(r, "auth-session")
		if err != nil {
			return err
		}

		session.Values["state"] = state
		if err = session.Save(r, w); err != nil {
			return err
		}

		http.Redirect(w, r, uri, http.StatusTemporaryRedirect)
		return nil
	}

	h.wrapper.Wrap(http.MethodGet, "/login", wrapH, mws...)
}

func (h *Handler) LoginCallback(mws ...server.Middleware) {
	wrapH := func(w http.ResponseWriter, r *http.Request) error {
		session, err := h.storage.Get(r, "auth-session")
		if err != nil {
			return err
		}

		if r.URL.Query().Get("state") != session.Values["state"] {
			return server.NewError("invalid state parameter", http.StatusForbidden)
		}

		session.Options.MaxAge = -1
		if err := session.Save(r, w); err != nil {
			return err
		}

		if r.URL.Query().Get("code") == "" {
			return server.NewError("invalid code parameter", http.StatusForbidden)
		}

		token, err := h.service.VerifyAuthentication(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			switch err {
			case service.ErrNotFound:
				return server.NewError(err.Error(), http.StatusNotFound)
			case service.ErrVerification:
				return server.NewError(err.Error(), http.StatusForbidden)
			}

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

	h.wrapper.Wrap(http.MethodGet, "/login/callback", wrapH, mws...)
}

func (h *Handler) Logout(mws ...server.Middleware) {
	wrapH := func(w http.ResponseWriter, r *http.Request) error {
		c, err := r.Cookie("token")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				return nil
			}

			return err
		}

		c.MaxAge = -1
		http.SetCookie(w, c)

		return nil
	}

	h.wrapper.Wrap(http.MethodGet, "/logout", wrapH, mws...)
}

func (h *Handler) Me(mws ...server.Middleware) {
	wrapH := func(w http.ResponseWriter, r *http.Request) error {
		token := r.Header.Get("Authorization")

		myInformation, err := h.service.GetMyInformation(token)
		if err != nil {
			if errors.Is(err, service.ErrParse) {
				return server.NewError(err.Error(), http.StatusForbidden)
			}

			return err
		}

		return server.RespondJSON(w, myInformation, http.StatusOK)
	}

	h.wrapper.Wrap(http.MethodGet, "/me", wrapH, mws...)
}
