package web

import "fmt"

const (
	_defaultPort   = ":8080"
)

type options struct {
	port string
}

type Option func(opts *options)

func WithPort(port string) Option {
	return func(opts *options) {
		if port == "" {
			port = _defaultPort
		}

		if string(port[0]) != ":" {
			port = fmt.Sprintf(":%s", port)
		}

		opts.port = port
	}
}

func defaultOptions() *options {
	return &options{port: _defaultPort}
}
