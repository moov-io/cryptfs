package stream

import (
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// chunkReader reads and decrypts chunks from the underlying reader.
type chunkReader struct {
	src         io.Reader
	gcm         cipher.AEAD
	noncePrefix [noncePrefixSize]byte
	headerAAD   []byte // for verifying first chunk
	buf         []byte // unconsumed plaintext from current chunk
	counter     uint64
	done        bool
}

func (cr *chunkReader) Read(p []byte) (int, error) {
	if len(cr.buf) > 0 {
		n := copy(p, cr.buf)
		cr.buf = cr.buf[n:]
		return n, nil
	}

	if cr.done {
		return 0, io.EOF
	}

	if err := cr.readNextChunk(); err != nil {
		return 0, err
	}

	if cr.done {
		return 0, io.EOF
	}

	n := copy(p, cr.buf)
	cr.buf = cr.buf[n:]
	return n, nil
}

func (cr *chunkReader) readNextChunk() error {
	// Read 4-byte chunk length
	var lenBuf [4]byte
	if _, err := io.ReadFull(cr.src, lenBuf[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("unexpected end of stream reading chunk length: %w", err)
		}
		return fmt.Errorf("reading chunk length: %w", err)
	}

	chunkLen := binary.BigEndian.Uint32(lenBuf[:])

	// End marker
	if chunkLen == 0 {
		cr.done = true
		return nil
	}

	// Read the chunk (nonce + ciphertext + tag)
	chunk := make([]byte, chunkLen)
	if _, err := io.ReadFull(cr.src, chunk); err != nil {
		return fmt.Errorf("reading chunk data: %w", err)
	}

	if len(chunk) < nonceSize {
		return errors.New("chunk too small to contain nonce")
	}

	// Verify nonce counter
	expectedNonce := buildNonce(cr.noncePrefix, cr.counter)
	var actualNonce [nonceSize]byte
	copy(actualNonce[:], chunk[:nonceSize])
	if actualNonce != expectedNonce {
		return fmt.Errorf("nonce counter mismatch at chunk %d", cr.counter)
	}

	// For chunk 0, pass the serialized header as AAD (Additional Authenticated Data).
	// GCM.Open will recompute the auth tag using this AAD and fail if it doesn't match
	// what was used during Seal — this cryptographically binds the header to the data,
	// so any tampering with flags, nonce prefix, or wrapped key causes decryption to fail.
	var aad []byte
	if cr.counter == 0 {
		aad = cr.headerAAD
	}

	plaintext, err := cr.gcm.Open(nil, chunk[:nonceSize], chunk[nonceSize:], aad)
	if err != nil {
		return fmt.Errorf("decrypting chunk %d: %w", cr.counter, err)
	}

	cr.buf = plaintext
	cr.counter++
	return nil
}

// Reader is the public streaming decryption reader.
type Reader struct {
	chunks     *chunkReader
	gzipReader *gzip.Reader // nil if no compression
	closer     io.Closer    // underlying source to close
}

// NewReader returns a streaming decryption reader. It reads the CRFS header,
// unwraps the data key, and returns a reader that decrypts and decompresses on Read.
// The caller must call Close on the returned Reader.
func NewReader(src io.Reader, kp KeyProvider) (*Reader, error) {
	h, aad, err := readHeader(src)
	if err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}

	var key []byte
	if len(h.WrappedKey) > 0 {
		key, err = kp.UnwrapKey(h.WrappedKey)
		if err != nil {
			return nil, fmt.Errorf("unwrapping data key: %w", err)
		}
	} else {
		dk, err := kp.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("getting key: %w", err)
		}
		key = dk.Plaintext
	}

	compress := h.Flags&flagGzip != 0
	return newReader(src, key, aad, compress)
}

func newReader(src io.Reader, key []byte, headerAAD []byte, compress bool) (*Reader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	var prefix [noncePrefixSize]byte
	copy(prefix[:], headerAAD[6:13])

	cr := &chunkReader{
		src:         src,
		gcm:         gcm,
		noncePrefix: prefix,
		headerAAD:   headerAAD,
	}

	r := &Reader{chunks: cr}

	if closer, ok := src.(io.Closer); ok {
		r.closer = closer
	}

	if compress {
		// Need to read at least one chunk to initialize gzip reader
		if err := cr.readNextChunk(); err != nil {
			return nil, fmt.Errorf("reading first chunk for gzip: %w", err)
		}
		gz, err := gzip.NewReader(cr)
		if err != nil {
			return nil, fmt.Errorf("creating gzip reader: %w", err)
		}
		r.gzipReader = gz
	}

	return r, nil
}

func (r *Reader) Read(p []byte) (int, error) {
	if r.gzipReader != nil {
		return r.gzipReader.Read(p)
	}
	return r.chunks.Read(p)
}

// Close closes the reader and the underlying source (if it implements io.Closer).
func (r *Reader) Close() error {
	var errs []error
	if r.gzipReader != nil {
		if err := r.gzipReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if r.closer != nil {
		if err := r.closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
