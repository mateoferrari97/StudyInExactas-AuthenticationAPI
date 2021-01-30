package web

import (
	"github.com/stretchr/testify/require"
	"net/http"
	"strings"
	"testing"
)

func TestServer_Wrap(t *testing.T) {
	// Given
	s := NewServer()
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:8080/test", nil)
	client := http.DefaultClient

	// When
	s.Wrap(http.MethodGet, "/test", func(w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	go s.Run()

	// Then
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServer_Wrap_WithMiddleware(t *testing.T) {
	// Given
	s := NewServer(WithPort(":8081"))
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:8081/test", nil)
	client := http.DefaultClient

	var results []string
	h := func(w http.ResponseWriter, r *http.Request) error {
		results = append(results, "h()")
		return nil
	}

	mwg := func() Middleware {
		return func(h http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				results = append(results, "mwg()")
				h(w, r)
			}
		}
	}

	mwh := func() Middleware {
		return func(h http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				results = append(results, "mwh()")
				h(w, r)
			}
		}
	}

	// When
	s.Wrap(http.MethodGet, "/test", h, mwg(), mwh())

	go s.Run()

	// Then
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Len(t, results, 3)
	require.Equal(t, "mwg()->mwh()->h()", strings.Join(results, "->") )
}
