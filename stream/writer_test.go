package stream

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriterRoundTrip(t *testing.T) {
	key := []byte("1234567890123456") // AES-128

	t.Run("small data no compression", func(t *testing.T) {
		original := []byte("hello, world")
		buf := writeTestData(t, key, original, false, 0)

		got := readTestData(t, key, buf.Bytes())
		require.Equal(t, original, got)
	})

	t.Run("small data with compression", func(t *testing.T) {
		original := []byte("hello, world")
		buf := writeTestData(t, key, original, true, 0)

		got := readTestData(t, key, buf.Bytes())
		require.Equal(t, original, got)
	})

	t.Run("exact chunk boundary", func(t *testing.T) {
		original := make([]byte, DefaultChunkSize)
		_, err := rand.Read(original)
		require.NoError(t, err)

		buf := writeTestData(t, key, original, false, 0)

		got := readTestData(t, key, buf.Bytes())
		require.Equal(t, original, got)
	})

	t.Run("multiple chunks", func(t *testing.T) {
		original := make([]byte, DefaultChunkSize*3+42)
		_, err := rand.Read(original)
		require.NoError(t, err)

		buf := writeTestData(t, key, original, false, 0)

		got := readTestData(t, key, buf.Bytes())
		require.Equal(t, original, got)
	})

	t.Run("small chunk size", func(t *testing.T) {
		original := []byte("The quick brown fox jumps over the lazy dog")
		buf := writeTestData(t, key, original, false, 10)

		got := readTestData(t, key, buf.Bytes())
		require.Equal(t, original, got)
	})

	t.Run("empty data", func(t *testing.T) {
		buf := writeTestData(t, key, nil, false, 0)

		got := readTestData(t, key, buf.Bytes())
		require.Empty(t, got)
	})

	t.Run("large data with compression", func(t *testing.T) {
		original := bytes.Repeat([]byte("abcdefghij"), 100_000) // 1MB of compressible data
		buf := writeTestData(t, key, original, true, 0)

		// Compressed + encrypted should be smaller than original
		require.Less(t, buf.Len(), len(original))

		got := readTestData(t, key, buf.Bytes())
		require.Equal(t, original, got)
	})

	t.Run("incremental writes", func(t *testing.T) {
		var prefix [noncePrefixSize]byte
		_, err := rand.Read(prefix[:])
		require.NoError(t, err)

		h := &fileHeader{
			Version:     formatVersion,
			Flags:       0,
			NoncePrefix: prefix,
		}

		var buf bytes.Buffer
		err = writeHeader(&buf, h)
		require.NoError(t, err)

		w, err := newWriter(&buf, key, h, false, 16)
		require.NoError(t, err)

		// Write data in small increments
		for i := 0; i < 10; i++ {
			_, err := w.Write([]byte("hello"))
			require.NoError(t, err)
		}
		require.NoError(t, w.Close())

		got := readTestData(t, key, buf.Bytes())
		require.Equal(t, bytes.Repeat([]byte("hello"), 10), got)
	})
}

func TestNewWriterRoundTrip(t *testing.T) {
	key := []byte("1234567890123456")
	kp := NewStaticKeyProvider(key)

	t.Run("without compression", func(t *testing.T) {
		original := []byte("hello, streaming world")

		var buf bytes.Buffer
		w, err := NewWriter(&buf, kp)
		require.NoError(t, err)
		_, err = w.Write(original)
		require.NoError(t, err)
		require.NoError(t, w.Close())

		r, err := NewReader(bytes.NewReader(buf.Bytes()), kp)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NoError(t, r.Close())
		require.Equal(t, original, got)
	})

	t.Run("with compression", func(t *testing.T) {
		original := []byte(bytes.Repeat([]byte("hello world "), 10_000))

		var buf bytes.Buffer
		w, err := NewWriter(&buf, kp, WithCompression())
		require.NoError(t, err)
		_, err = w.Write(original)
		require.NoError(t, err)
		require.NoError(t, w.Close())

		r, err := NewReader(bytes.NewReader(buf.Bytes()), kp)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NoError(t, r.Close())
		require.Equal(t, original, got)
	})

	t.Run("with custom chunk size", func(t *testing.T) {
		original := []byte("The quick brown fox jumps over the lazy dog")

		var buf bytes.Buffer
		w, err := NewWriter(&buf, kp, WithChunkSize(10))
		require.NoError(t, err)
		_, err = w.Write(original)
		require.NoError(t, err)
		require.NoError(t, w.Close())

		r, err := NewReader(bytes.NewReader(buf.Bytes()), kp)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NoError(t, r.Close())
		require.Equal(t, original, got)
	})
}

func TestWriterUseAfterClose(t *testing.T) {
	key := []byte("1234567890123456")
	kp := NewStaticKeyProvider(key)

	t.Run("Write after Close returns ErrClosed", func(t *testing.T) {
		var buf bytes.Buffer
		w, err := NewWriter(&buf, kp)
		require.NoError(t, err)

		_, err = w.Write([]byte("hello"))
		require.NoError(t, err)
		require.NoError(t, w.Close())

		_, err = w.Write([]byte("world"))
		require.ErrorIs(t, err, ErrClosed)
	})

	t.Run("double Close returns ErrClosed", func(t *testing.T) {
		var buf bytes.Buffer
		w, err := NewWriter(&buf, kp)
		require.NoError(t, err)

		require.NoError(t, w.Close())
		require.ErrorIs(t, w.Close(), ErrClosed)
	})

	t.Run("sticky error after write failure", func(t *testing.T) {
		fw := &failWriter{failAfter: 1} // fail on the second Write call (chunk data)
		var prefix [noncePrefixSize]byte
		_, err := rand.Read(prefix[:])
		require.NoError(t, err)

		h := &fileHeader{
			Version:     formatVersion,
			NoncePrefix: prefix,
		}
		// Use a tiny chunk size so a single Write triggers a flush to dst
		w, err := newWriter(fw, key, h, false, 4)
		require.NoError(t, err)

		// Write enough to fill a chunk and trigger a flush, which writes
		// the 4-byte length (succeeds) then the chunk data (fails).
		_, firstErr := w.Write([]byte("abcdefgh"))
		require.Error(t, firstErr)

		// Subsequent write returns the same sticky error
		_, secondErr := w.Write([]byte("more"))
		require.Equal(t, firstErr, secondErr)
	})
}

func writeTestData(t *testing.T, key, data []byte, compress bool, chunkSize int) *bytes.Buffer {
	t.Helper()

	var prefix [noncePrefixSize]byte
	_, err := rand.Read(prefix[:])
	require.NoError(t, err)

	var flags byte
	if compress {
		flags = flagGzip
	}

	h := &fileHeader{
		Version:     formatVersion,
		Flags:       flags,
		NoncePrefix: prefix,
	}

	var buf bytes.Buffer
	err = writeHeader(&buf, h)
	require.NoError(t, err)

	w, err := newWriter(&buf, key, h, compress, chunkSize)
	require.NoError(t, err)

	if len(data) > 0 {
		_, err = w.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())

	return &buf
}

// failWriter is an io.Writer that returns an error after a set number of calls.
type failWriter struct {
	failAfter int // number of successful Write calls before failing
	calls     int
}

func (fw *failWriter) Write(p []byte) (int, error) {
	if fw.calls >= fw.failAfter {
		return 0, fmt.Errorf("simulated write error")
	}
	fw.calls++
	return len(p), nil
}

func readTestData(t *testing.T, key, data []byte) []byte {
	t.Helper()

	r := bytes.NewReader(data)
	h, aad, err := readHeader(r)
	require.NoError(t, err)

	compress := h.Flags&flagGzip != 0
	dr, err := newReader(r, key, aad, compress)
	require.NoError(t, err)

	got, err := io.ReadAll(dr)
	require.NoError(t, err)
	require.NoError(t, dr.Close())
	return got
}
