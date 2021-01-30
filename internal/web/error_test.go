package web

import (
	"errors"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestNewError(t *testing.T) {
	// Given
	e := NewError(http.StatusInternalServerError, "something wrong happened")

	// When
	m := e.Error()

	// Then
	require.Equal(t, "Internal Server Error: something wrong happened", m)
}

func TestNewErrorf(t *testing.T) {
	// Given
	e := NewErrorf(http.StatusInternalServerError, "something wrong happened: %v", errors.New("another error"))

	// When
	m := e.Error()

	// Then
	require.Equal(t, "Internal Server Error: something wrong happened: another error", m)
}


func TestError(t *testing.T) {
	tt := []struct {
		name string
		err  error
	}{
		{
			name: "0 status code",
			err:  NewError( 0, "0 status code"),
		},
		{
			name: "empty message",
			err:  NewError(http.StatusInternalServerError, ""),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// Given
			e := tc.err

			// When
			m := e.Error()

			// Then
			require.Equal(t, "unexpected error", m)
		})
	}
}

