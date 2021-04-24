package service

import (
	"context"
	"errors"
	auth2 "github.com/mateoferrari97/Users-API/cmd/server/internal/service/auth"
	jwt2 "github.com/mateoferrari97/Users-API/cmd/server/internal/service/jwt"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/mock"
)

type authenticatorMock struct {
	mock.Mock
}

func (a *authenticatorMock) CreateAuthentication() (uri, state string, err error) {
	args := a.Called()
	return args.String(0), args.String(1), args.Error(2)
}

func (a *authenticatorMock) VerifyAuthentication(ctx context.Context, code string) (idToken *oidc.IDToken, err error) {
	args := a.Called(ctx, code)
	return args.Get(0).(*oidc.IDToken), args.Error(1)
}

type jwtMock struct {
	mock.Mock
}

func (j *jwtMock) Create(v jwt2.UnmarshalClaims, subject string) (string, error) {
	args := j.Called(v, subject)
	return args.String(0), args.Error(1)
}

func (j *jwtMock) Claims(signedToken string) (jwt2.Claims, error) {
	args := j.Called(signedToken)
	return args.Get(0).(jwt2.Claims), args.Error(1)
}

func TestService_CreateAuthentication(t *testing.T) {
	// Given
	jwt_ := jwtMock{}
	authenticator := authenticatorMock{}
	authenticator.On("CreateAuthentication").Return("uri", "state", nil)

	s := NewService(&authenticator, &jwt_)

	// When
	uri, state, err := s.CreateAuthentication()
	if err != nil {
		t.Fatal(err)
	}

	// Then
	require.Equal(t, "uri", uri)
	require.Equal(t, "state", state)
}

func TestService_CreateAuthentication_Error(t *testing.T) {
	// Given
	jwt_ := jwtMock{}
	authenticator := authenticatorMock{}
	authenticator.On("CreateAuthentication").Return("", "", errors.New("error"))

	s := NewService(&authenticator, &jwt_)

	// When
	_, _, err := s.CreateAuthentication()
	if err == nil {
		t.Fatal("test must fail")
	}

	// Then
	require.EqualError(t, err, "error")
}

func TestService_VerifyAuthentication(t *testing.T) {
	// Given
	ctx := context.Background()
	idToken := &oidc.IDToken{Subject: "google-oauth2"}
	code := "_code_"

	authenticator := authenticatorMock{}
	authenticator.On("VerifyAuthentication", ctx, code).Return(idToken, nil)

	jwt_ := jwtMock{}
	jwt_.On("Create", idToken, "google-oauth2").Return("token", nil)

	s := NewService(&authenticator, &jwt_)

	// When
	token, err := s.VerifyAuthentication(ctx, code)
	if err != nil {
		t.Fatal(err)
	}

	// Then
	require.Equal(t, "token", token)
}

func TestService_VerifyAuthentication_VerifyAuthenticationErrors(t *testing.T) {
	tt := []struct {
		name          string
		returnedError error
		expectedError string
	}{
		{
			name:          "generic error",
			returnedError: errors.New("error"),
			expectedError: "could not verify authentication: error",
		},
		{
			name:          "not found error",
			returnedError: auth2.ErrNotFound,
			expectedError: "could not verify authentication: service: resource not found",
		},
		{
			name:          "authentication error",
			returnedError: auth2.ErrAuthenticationFailed,
			expectedError: "could not verify authentication: service: could not verify resource",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// Given
			ctx := context.Background()
			code := "_code_"

			jwt_ := jwtMock{}
			authenticator := authenticatorMock{}
			authenticator.On("VerifyAuthentication", ctx, code).Return(&oidc.IDToken{}, tc.returnedError)

			s := NewService(&authenticator, &jwt_)

			// When
			_, err := s.VerifyAuthentication(ctx, code)
			if err == nil {
				t.Fatal("test must fail")
			}

			// Then
			require.EqualError(t, err, tc.expectedError)
		})
	}
}

func TestService_VerifyAuthentication_JWTCreateTokenErrors(t *testing.T) {
	tt := []struct {
		name          string
		returnedError error
		expectedError string
	}{
		{
			name:          "generic error",
			returnedError: errors.New("error"),
			expectedError: "could not create token: error",
		},
		{
			name:          "not found error",
			returnedError: jwt2.ErrNotFound,
			expectedError: "could not create token: service: could not create resource",
		},
		{
			name:          "unsupported provider error",
			returnedError: jwt2.ErrUnsupportedProvider,
			expectedError: "could not create token: service: could not create resource",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// Given
			ctx := context.Background()
			idToken := &oidc.IDToken{Subject: "google-oauth2"}
			code := "_code_"

			authenticator := authenticatorMock{}
			authenticator.On("VerifyAuthentication", ctx, code).Return(idToken, nil)

			jwt_ := jwtMock{}
			jwt_.On("Create", idToken, "google-oauth2").Return("", tc.returnedError)

			s := NewService(&authenticator, &jwt_)

			// When
			_, err := s.VerifyAuthentication(ctx, code)
			if err == nil {
				t.Fatal("test must fail")
			}

			// Then
			require.EqualError(t, err, tc.expectedError)
		})
	}
}

type claimsMock struct {
	mock.Mock
}

func (c *claimsMock) Valid() error {
	return nil
}

func TestService_GetMyInformation(t *testing.T) {
	// Given
	authenticator := authenticatorMock{}
	jwt_ := jwtMock{}
	jwt_.On("Claims", "token").Return(&claimsMock{}, nil)

	s := NewService(&authenticator, &jwt_)

	// When
	myInformation, err := s.GetMyInformation("Bearer token")
	if err != nil {
		t.Fatal(err)
	}

	// Then
	require.NotNil(t, myInformation)
}

func TestService_GetMyInformation_InvalidTokenLengthError(t *testing.T) {
	// Given
	authenticator := authenticatorMock{}
	jwt_ := jwtMock{}

	s := NewService(&authenticator, &jwt_)

	// When
	_, err := s.GetMyInformation("token")
	if err == nil {
		t.Fatal("test must fail")
	}

	// Then
	require.EqualError(t, err, "invalid token length: service: could not parse resource")
}

func TestService_GetMyInformation_GetClaimsError(t *testing.T) {
	tt := []struct {
		name          string
		returnedError error
		expectedError string
	}{
		{
			name:          "generic error",
			returnedError: errors.New("error"),
			expectedError: "error",
		},
		{
			name:          "malformed token error",
			returnedError: jwt2.ErrMalformedToken,
			expectedError: "could not fetch claims: service: could not create resource",
		},
		{
			name:          "expired token error",
			returnedError: jwt2.ErrExpiredToken,
			expectedError: "could not fetch claims: service: could not create resource",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// Given
			authenticator := authenticatorMock{}
			jwt_ := jwtMock{}
			jwt_.On("Claims", "token").Return(&claimsMock{}, tc.returnedError)

			s := NewService(&authenticator, &jwt_)

			// When
			_, err := s.GetMyInformation("Bearer token")
			if err == nil {
				t.Fatal("test must fail")
			}

			// Then
			require.EqualError(t, err, tc.expectedError)
		})
	}
}