package internal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mateoferrari97/AnitiMonono-AuthenticationAPI/cmd/server/internal/authentication"
	"github.com/mateoferrari97/Kit/web/server"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type wrapperMock struct {
	f server.HandlerFunc
}

func (w *wrapperMock) Wrap(_, _ string, f server.HandlerFunc, _ ...server.Middleware) {
	w.f = f
}

type serviceMock struct {
	mock.Mock
}

func (s *serviceMock) CreateAuthentication() (url, state string, err error) {
	args := s.Called()
	return args.String(0), args.String(1), args.Error(2)
}

func (s *serviceMock) VerifyAuthentication(ctx context.Context, code string) (string, error) {
	args := s.Called(ctx, code)
	return args.String(0), args.Error(1)
}

func (s *serviceMock) GetMyInformation(token string) ([]byte, error) {
	args := s.Called(token)
	return args.Get(0).([]byte), args.Error(1)
}

type storageMock struct {
	mock.Mock
}

func (s *storageMock) Get(r *http.Request, name string) (*sessions.Session, error) {
	args := s.Called(r, name)
	return args.Get(0).(*sessions.Session), args.Error(1)
}

func (s *storageMock) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	panic("implement me")
}

type storeMock struct {
	mock.Mock
}

func (ss *storeMock) Get(r *http.Request, name string) (*sessions.Session, error) {
	args := ss.Called(r, name)
	return args.Get(0).(*sessions.Session), args.Error(1)
}

func (ss *storeMock) New(r *http.Request, name string) (*sessions.Session, error) {
	panic("implement me")
}

func (ss *storeMock) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	args := ss.Called(r, w, s)
	return args.Error(0)
}

func TestHandler_Login(t *testing.T) {
	// Given
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)

	wrapper := wrapperMock{}
	service_ := serviceMock{}
	service_.On("CreateAuthentication").Return("uri", "state", nil)

	storage := storageMock{}
	store := storeMock{}

	session := sessions.NewSession(&store, "auth-session")
	storage.On("Get", r, "auth-session").Return(session, nil)
	store.On("Save", r, w, session).Return(nil)

	h := NewHandler(&wrapper, &service_, &storage)
	h.Login()

	// When
	err := wrapper.f(w, r)
	if err != nil {
		t.Fatal(err)
	}

	// Then
	require.Equal(t, http.StatusTemporaryRedirect, w.Code)
}

func TestHandler_Login_CreateAuthenticationError(t *testing.T) {
	// Given
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)

	wrapper := wrapperMock{}
	service_ := serviceMock{}
	service_.On("CreateAuthentication").Return("", "", errors.New("error"))

	h := NewHandler(&wrapper, &service_, nil)
	h.Login()

	// When
	err := wrapper.f(w, r)
	if err == nil {
		t.Fatal("test should fail")
	}

	// Then
	require.EqualError(t, err, "error")
}

func TestHandler_Login_GetSessionFromStorageError(t *testing.T) {
	// Given
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)

	wrapper := wrapperMock{}
	service_ := serviceMock{}
	service_.On("CreateAuthentication").Return("uri", "state", nil)

	storage := storageMock{}
	storage.On("Get", r, "auth-session").Return(&sessions.Session{}, errors.New("error"))

	h := NewHandler(&wrapper, &service_, &storage)
	h.Login()

	// When
	err := wrapper.f(w, r)
	if err == nil {
		t.Fatal("test should fail")
	}

	// Then
	require.EqualError(t, err, "error")
}

func TestHandler_Login_SessionSaveError(t *testing.T) {
	// Given
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)

	wrapper := wrapperMock{}
	service_ := serviceMock{}
	service_.On("CreateAuthentication").Return("uri", "state", nil)

	storage := storageMock{}
	store := storeMock{}

	session := sessions.NewSession(&store, "auth-session")
	storage.On("Get", r, "auth-session").Return(session, nil)
	store.On("Save", r, w, session).Return(errors.New("error"))

	h := NewHandler(&wrapper, &service_, &storage)
	h.Login()

	// When
	err := wrapper.f(w, r)
	if err == nil {
		t.Fatal("test should fail")
	}

	// Then
	require.EqualError(t, err, "error")
}

func TestHandler_LoginCallback(t *testing.T) {
	// Given
	store := storeMock{}
	session := sessions.NewSession(&store, "auth-session")
	session.Values["state"] = "_state_"

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)
	q := r.URL.Query()

	q.Add("state", "_state_")
	q.Add("code", "_code_")
	r.URL.RawQuery = q.Encode()

	ctx := context.Background()
	r = r.WithContext(ctx)

	store.On("Save", r, w, session).Return(nil)

	service_ := serviceMock{}
	service_.On("VerifyAuthentication", ctx, "_code_").Return("token", nil)

	wrapper := wrapperMock{}
	storage := storageMock{}
	storage.On("Get", r, "auth-session").Return(session, nil)

	h := NewHandler(&wrapper, &service_, &storage)
	h.LoginCallback()

	// When
	err := wrapper.f(w, r)
	if err != nil {
		t.Fatal(err)
	}

	// Then
	require.Equal(t, http.StatusOK, w.Code)

	cookies := w.Header().Values("Set-Cookie")
	require.Len(t, cookies, 1)
	require.Equal(t, cookies[0], "token=token; Path=/; HttpOnly")
}

func TestHandler_LoginCallback_GetSessionFromStorageError(t *testing.T) {
	// Given
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)

	service_ := serviceMock{}
	wrapper := wrapperMock{}
	storage := storageMock{}
	storage.On("Get", r, "auth-session").Return(&sessions.Session{}, errors.New("error"))

	h := NewHandler(&wrapper, &service_, &storage)
	h.LoginCallback()

	// When
	err := wrapper.f(w, r)
	if err == nil {
		t.Fatal("test must fail")
	}

	// Then
	require.EqualError(t, err, "error")
}

func TestHandler_LoginCallback_InvalidStateParameter(t *testing.T) {
	// Given
	store := storeMock{}
	session := sessions.NewSession(&store, "auth-session")
	session.Values["state"] = "_state_"

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)
	q := r.URL.Query()

	q.Add("state", "_state2_")
	r.URL.RawQuery = q.Encode()

	service_ := serviceMock{}
	wrapper := wrapperMock{}
	storage := storageMock{}
	storage.On("Get", r, "auth-session").Return(session, nil)

	h := NewHandler(&wrapper, &service_, &storage)
	h.LoginCallback()

	// When
	err := wrapper.f(w, r)
	if err == nil {
		t.Fatal("test must fail")
	}

	// Then
	require.EqualError(t, err, "403 forbidden: invalid state parameter")
}

func TestHandler_LoginCallback_SessionSaveError(t *testing.T) {
	// Given
	store := storeMock{}
	session := sessions.NewSession(&store, "auth-session")
	session.Values["state"] = "_state_"

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)
	q := r.URL.Query()

	q.Add("state", "_state_")
	r.URL.RawQuery = q.Encode()

	ctx := context.Background()
	r = r.WithContext(ctx)

	store.On("Save", r, w, session).Return(errors.New("error"))

	service_ := serviceMock{}
	wrapper := wrapperMock{}
	storage := storageMock{}
	storage.On("Get", r, "auth-session").Return(session, nil)

	h := NewHandler(&wrapper, &service_, &storage)
	h.LoginCallback()

	// When
	err := wrapper.f(w, r)
	if err == nil {
		t.Fatal("test must fail")
	}

	// Then
	require.EqualError(t, err, "error")
}

func TestHandler_LoginCallback_CodeIsMissing(t *testing.T) {
	// Given
	store := storeMock{}
	session := sessions.NewSession(&store, "auth-session")
	session.Values["state"] = "_state_"

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)
	q := r.URL.Query()

	q.Add("state", "_state_")
	q.Add("code", "")
	r.URL.RawQuery = q.Encode()

	ctx := context.Background()
	r = r.WithContext(ctx)

	store.On("Save", r, w, session).Return(nil)

	service_ := serviceMock{}
	wrapper := wrapperMock{}
	storage := storageMock{}
	storage.On("Get", r, "auth-session").Return(session, nil)

	h := NewHandler(&wrapper, &service_, &storage)
	h.LoginCallback()

	// When
	err := wrapper.f(w, r)
	if err == nil {
		t.Fatal("test must fail")
	}

	// Then
	require.EqualError(t, err, "403 forbidden: invalid code parameter")
}

func TestHandler_LoginCallback_VerifyAuthenticationError(t *testing.T) {
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
			name:          "not found error",
			returnedError: authentication.ErrNotFound,
			expectedError: "404 not_found: authentication: resource not found",
		},
		{
			name:          "verification error",
			returnedError: authentication.ErrVerification,
			expectedError: "403 forbidden: authentication: could not verify resource",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			// Given
			store := storeMock{}
			session := sessions.NewSession(&store, "auth-session")
			session.Values["state"] = "_state_"

			w := httptest.NewRecorder()
			r, _ := http.NewRequest("GET", "whocares", nil)
			q := r.URL.Query()

			q.Add("state", "_state_")
			q.Add("code", "_code_")
			r.URL.RawQuery = q.Encode()

			ctx := context.Background()
			r = r.WithContext(ctx)

			store.On("Save", r, w, session).Return(nil)

			service_ := serviceMock{}
			service_.On("VerifyAuthentication", ctx, "_code_").Return("", tc.returnedError)

			wrapper := wrapperMock{}
			storage := storageMock{}
			storage.On("Get", r, "auth-session").Return(session, nil)

			h := NewHandler(&wrapper, &service_, &storage)
			h.LoginCallback()

			// When
			err := wrapper.f(w, r)
			if err == nil {
				t.Fatal("test must fail")
			}

			// Then
			require.EqualError(t, err, tc.expectedError)
		})
	}
}

func TestHandler_Logout(t *testing.T) {
	// Given
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)
	r.AddCookie(&http.Cookie{Name: "token", Value: "_token_"})

	wrapper := wrapperMock{}
	service_ := serviceMock{}
	storage := storageMock{}

	h := NewHandler(&wrapper, &service_, &storage)
	h.Logout()

	// When
	err := wrapper.f(w, r)
	if err != nil {
		t.Fatal(err)
	}

	// Then
	require.Equal(t, http.StatusOK, w.Code)

	cookies := w.Header().Values("Set-Cookie")
	require.Len(t, cookies, 1)
	require.Equal(t, "token=_token_; Max-Age=0", cookies[0])
}

func TestHandler_Logout_TokenCookieNotFound(t *testing.T) {
	// Given
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)

	wrapper := wrapperMock{}
	service_ := serviceMock{}
	storage := storageMock{}

	h := NewHandler(&wrapper, &service_, &storage)
	h.Logout()

	// When
	err := wrapper.f(w, r)
	if err != nil {
		t.Fatal(err)
	}

	// Then
	require.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_Me(t *testing.T) {
	// Given
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)
	r.Header.Add("Authorization", "Bearer _token_")

	wrapper := wrapperMock{}
	storage := storageMock{}
	service_ := serviceMock{}
	service_.On("GetMyInformation", "Bearer _token_").Return([]byte(`{"name":"example"}`), nil)

	h := NewHandler(&wrapper, &service_, &storage)
	h.Me()

	// When
	err := wrapper.f(w, r)
	if err != nil {
		t.Fatal(err)
	}

	// Then
	var body struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}

	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "example", body.Name)
}

func TestHandler_Me_GetMyInformationParsingTokenError(t *testing.T) {
	// Given
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)
	r.Header.Add("Authorization", "Bearer _token_")

	wrapper := wrapperMock{}
	storage := storageMock{}
	service_ := serviceMock{}
	service_.On("GetMyInformation", "Bearer _token_").Return([]byte{}, authentication.ErrParse)

	h := NewHandler(&wrapper, &service_, &storage)
	h.Me()

	// When
	err := wrapper.f(w, r)
	if err == nil {
		t.Fatal("test must fail")
	}

	// Then
	require.EqualError(t, err, "403 forbidden: authentication: could not parse resource")
}

func TestHandler_Me_GetMyInformationError(t *testing.T) {
	// Given
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "whocares", nil)
	r.Header.Add("Authorization", "Bearer _token_")

	wrapper := wrapperMock{}
	storage := storageMock{}
	service_ := serviceMock{}
	service_.On("GetMyInformation", "Bearer _token_").Return([]byte{}, errors.New("error"))

	h := NewHandler(&wrapper, &service_, &storage)
	h.Me()

	// When
	err := wrapper.f(w, r)
	if err == nil {
		t.Fatal("test must fail")
	}

	// Then
	require.EqualError(t, err, "error")
}
