package stream

type options struct {
	compress  bool
	chunkSize int
}

// Option configures streaming encryption behavior.
type Option func(*options)

// WithCompression enables gzip compression before encryption.
func WithCompression() Option {
	return func(o *options) {
		o.compress = true
	}
}

// WithChunkSize sets the plaintext chunk size (default 64KB).
func WithChunkSize(size int) Option {
	return func(o *options) {
		o.chunkSize = size
	}
}
