package web

import (
	"errors"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

type Server struct {
	opts   *options
	router *mux.Router
}

func NewServer(opts ...Option) *Server {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	router := mux.NewRouter()
	return &Server{
		opts:   options,
		router: router,
	}
}

func (s *Server) Run() error {
	port := s.opts.port

	s.Wrap(http.MethodGet, "/ping", func(w http.ResponseWriter, r *http.Request) error {
		return RespondJSON(w, "pong", http.StatusOK)
	})

	log.Printf("Listening on port %s", port)

	return http.ListenAndServe(port, s.router)
}

type Handler func(w http.ResponseWriter, r *http.Request) error

type Middleware func(h http.HandlerFunc) http.HandlerFunc

func (s *Server) Wrap(method string, pattern string, handler Handler, mw ...Middleware) {
	s.router.HandleFunc(pattern, wrapHandler(handlerAdapter(handler), mw...)).Methods(method)
}

func wrapHandler(handler http.HandlerFunc, mws ...Middleware) http.HandlerFunc {
	length := len(mws) - 1
	for mw := length; mw >= 0; mw-- {
		h := mws[mw]
		if h != nil {
			handler = h(handler)
		}
	}

	return handler
}

func handlerAdapter(handler Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := handler(w, r)
		if err == nil {
			return
		}

		handleError(w, err)
	}
}

func handleError(w http.ResponseWriter, err error) {
	var statusCode int
	var webError *Error
	if errors.As(err, &webError) {
		statusCode = webError.StatusCode
	} else {
		statusCode = http.StatusInternalServerError
	}

	_ = RespondJSON(w, err, statusCode)
}
