package stream

import "errors"

// ErrClosed is returned when Write, Read, or Close is called on an already-closed Writer or Reader.
var ErrClosed = errors.New("stream: use of closed Writer or Reader")
