package web

const (
	_defaultPort   = ":8080"
)

type options struct {
	port string
}

type Option func(opts *options)

func WithPort(port string) Option {
	return func(opts *options) {
		opts.port = port
	}
}

func defaultOptions() *options {
	return &options{port: _defaultPort}
}
