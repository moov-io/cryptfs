package stream

import (
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// chunkWriter buffers plaintext and encrypts full chunks with AES-GCM.
type chunkWriter struct {
	dst         io.Writer
	gcm         cipher.AEAD
	noncePrefix [noncePrefixSize]byte
	headerAAD   []byte // serialized header, AAD (Additional Authorization Data) for first chunk only
	buf         []byte
	chunkSize   int
	counter     uint64
}

func (cw *chunkWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		space := cw.chunkSize - len(cw.buf)
		if space <= 0 {
			if err := cw.flushChunk(); err != nil {
				return written, err
			}
			continue
		}

		n := len(p)
		if n > space {
			n = space
		}
		cw.buf = append(cw.buf, p[:n]...)
		p = p[n:]
		written += n

		if len(cw.buf) >= cw.chunkSize {
			if err := cw.flushChunk(); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (cw *chunkWriter) flushChunk() error {
	if len(cw.buf) == 0 {
		return nil
	}

	nonce := buildNonce(cw.noncePrefix, cw.counter)

	var aad []byte
	if cw.counter == 0 {
		aad = cw.headerAAD
	}

	ciphertext := cw.gcm.Seal(nil, nonce[:], cw.buf, aad)

	// chunk = nonce + ciphertext (includes GCM tag)
	chunk := append(nonce[:], ciphertext...)

	// Write 4-byte chunk length
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(chunk))) //nolint:gosec // chunk size bounded by chunkSize + GCM overhead
	if _, err := cw.dst.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("writing chunk length: %w", err)
	}

	if _, err := cw.dst.Write(chunk); err != nil {
		return fmt.Errorf("writing chunk data: %w", err)
	}

	cw.buf = cw.buf[:0]
	cw.counter++
	return nil
}

func (cw *chunkWriter) Close() error {
	// Flush any remaining buffered data
	if err := cw.flushChunk(); err != nil {
		return err
	}

	// Write end marker (4 zero bytes)
	var endMarker [4]byte
	if _, err := cw.dst.Write(endMarker[:]); err != nil {
		return fmt.Errorf("writing end marker: %w", err)
	}
	return nil
}

// Writer is the public streaming encryption writer.
type Writer struct {
	chunks     *chunkWriter
	gzipWriter *gzip.Writer // nil if no compression
}

// NewWriter returns a streaming encryption writer. Data written to the returned
// Writer is compressed (if configured), encrypted in chunks, and written to dst.
// The caller must call Close on the returned Writer to finalize the stream.
func NewWriter(dst io.Writer, kp KeyProvider, opts ...Option) (*Writer, error) {
	o := options{}
	for _, fn := range opts {
		fn(&o)
	}

	dk, err := kp.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating data key: %w", err)
	}

	var prefix [noncePrefixSize]byte
	if _, err := rand.Read(prefix[:]); err != nil {
		return nil, fmt.Errorf("generating nonce prefix: %w", err)
	}

	var flags byte
	if o.compress {
		flags |= flagGzip
	}

	h := &fileHeader{
		Version:     formatVersion,
		Flags:       flags,
		NoncePrefix: prefix,
		WrappedKey:  dk.WrappedKey,
	}

	if err := writeHeader(dst, h); err != nil {
		return nil, fmt.Errorf("writing header: %w", err)
	}

	return newWriter(dst, dk.Plaintext, h, o.compress, o.chunkSize)
}

func newWriter(dst io.Writer, key []byte, h *fileHeader, compress bool, chunkSize int) (*Writer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	cw := &chunkWriter{
		dst:         dst,
		gcm:         gcm,
		noncePrefix: h.NoncePrefix,
		headerAAD:   headerBytes(h),
		buf:         make([]byte, 0, chunkSize),
		chunkSize:   chunkSize,
	}

	w := &Writer{chunks: cw}

	if compress {
		w.gzipWriter = gzip.NewWriter(cw)
	}

	return w, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.gzipWriter != nil {
		return w.gzipWriter.Write(p)
	}
	return w.chunks.Write(p)
}

// Close flushes all buffered data and writes the end marker.
// The caller is responsible for closing the underlying io.Writer.
func (w *Writer) Close() error {
	if w.gzipWriter != nil {
		if err := w.gzipWriter.Close(); err != nil {
			return fmt.Errorf("closing gzip writer: %w", err)
		}
	}
	return w.chunks.Close()
}
