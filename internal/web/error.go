package web

import (
	"fmt"
	"net/http"
)

type Error struct {
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
}

func NewError(statusCode int, message string,) *Error {
	return &Error{
		StatusCode: statusCode,
		Message:    message,
	}
}

func NewErrorf(statusCode int, format string, args ...interface{}) *Error {
	return &Error{
		StatusCode: statusCode,
		Message:    fmt.Sprintf(format, args...),
	}
}

func (e *Error) Error() string {
	if e == nil || e.StatusCode == 0 || e.Message == "" {
		return "unexpected error"
	}

	return fmt.Sprintf("%s: %s", http.StatusText(e.StatusCode), e.Message)
}