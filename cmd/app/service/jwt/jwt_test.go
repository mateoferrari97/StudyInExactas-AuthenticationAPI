package jwt

import (
	"encoding/json"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
)

type claims struct {
	b []byte

	mock.Mock
}

func newClaims() claims {
	return claims{b: []byte(`{
		"aud": "_aud_",
		"exp": 123,
		"iat": 321,
		"iss": "_iss_",
		"name": "_name",
		"email": "_email_",
		"picture": "_picture_",
		"sub": "_sub_"
	}`)}
}

func (c *claims) Valid() error {
	return c.Called().Error(0)
}

func (c *claims) Claims(v interface{}) error {
	if err := json.Unmarshal(c.b, v); err != nil {
		return err
	}

	return nil
}

func TestJWT_Create(t *testing.T) {
	// Given
	claims := newClaims()
	subject := "google-oauth2|..."

	jwt_ := NewJWT("signingKey")

	// When
	token, err := jwt_.Create(&claims, subject)
	if err != nil {
		t.Fatal(err)
	}

	// Then
	require.Equal(t, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtZXRhZGF0YSI6eyJuYW1lIjoiX25hbWUiLCJlbWFpbCI6Il9lbWFpbF8iLCJhdmF0YXJfdXJsIjoiX3BpY3R1cmVfIn0sImF1ZCI6Il9hdWRfIiwiZXhwIjoxMjMsImlhdCI6MzIxLCJpc3MiOiJfaXNzXyIsInN1YiI6Il9zdWJfIn0.9uHJQlMBKFbwkmfnYmdFghIKXhXYbO1sF0o9z3C9Mvg", token)
}

func TestJWT_Create_SubjectsError(t *testing.T) {
	// Given
	claims := newClaims()

	jwt_ := NewJWT("signingKey")

	// When
	_, err := jwt_.Create(&claims,"random subject")
	if err == nil {
		t.Fatal("test must fail")
	}

	// Then
	require.EqualError(t, err, "jwt: unsupported provider: got: (random subject), want: (google-oauth2 and windowslive)")
}
