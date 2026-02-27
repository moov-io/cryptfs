package stream

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// So we know that it's new format of the encrypted file
var magic = [4]byte{'C', 'R', 'F', 'S'}

const (
	formatVersion = 0x01

	flagGzip = 0x01

	noncePrefixSize = 7
	nonceSize       = 12 // 7-byte prefix + 5-byte counter

	// DefaultChunkSize is the plaintext size per chunk before encryption.
	DefaultChunkSize = 64 * 1024

	// fixedHeaderSize is magic(4) + version(1) + flags(1) + noncePrefix(7) + wrappedKeyLen(2) = 15
	fixedHeaderSize = 15
)

type fileHeader struct {
	Version     byte
	Flags       byte
	NoncePrefix [noncePrefixSize]byte
	WrappedKey  []byte
}

func writeHeader(w io.Writer, h *fileHeader) error {
	bs := headerBytes(h)
	_, err := w.Write(bs)
	return err
}

func readHeader(r io.Reader) (*fileHeader, []byte, error) {
	// readHeader is only called after the caller has already confirmed the CRFS
	// magic (e.g. Reveal checks the first 4 bytes before delegating here), so
	// consuming bytes from the reader is safe — we know it's the new format.
	var fixed [fixedHeaderSize]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return nil, nil, fmt.Errorf("reading header: %w", err)
	}

	if !bytes.Equal(fixed[0:4], magic[:]) {
		return nil, nil, errors.New("invalid magic bytes")
	}
	if fixed[4] != formatVersion {
		return nil, nil, fmt.Errorf("unsupported format version: %d", fixed[4])
	}

	h := &fileHeader{
		Version: fixed[4],
		Flags:   fixed[5],
	}
	copy(h.NoncePrefix[:], fixed[6:13])

	wkLen := binary.BigEndian.Uint16(fixed[13:15])
	if wkLen > 0 {
		h.WrappedKey = make([]byte, wkLen)
		if _, err := io.ReadFull(r, h.WrappedKey); err != nil {
			return nil, nil, fmt.Errorf("reading wrapped key: %w", err)
		}
	}

	bs := headerBytes(h)
	return h, bs, nil
}

func headerBytes(h *fileHeader) []byte {
	wkLen := len(h.WrappedKey)
	bs := make([]byte, fixedHeaderSize+wkLen)

	copy(bs[0:4], magic[:])
	bs[4] = h.Version
	bs[5] = h.Flags
	copy(bs[6:13], h.NoncePrefix[:])
	binary.BigEndian.PutUint16(bs[13:15], uint16(wkLen))

	if wkLen > 0 {
		copy(bs[fixedHeaderSize:], h.WrappedKey)
	}

	return bs
}

func buildNonce(prefix [noncePrefixSize]byte, counter uint64) [nonceSize]byte {
	var nonce [nonceSize]byte
	copy(nonce[:noncePrefixSize], prefix[:])

	// AES-GCM needs a 12-byte nonce. We use 7 bytes of random prefix (unique per file)
	// plus 5 bytes of counter (unique per chunk). 5 bytes = 40 bits = ~1 trillion chunks,
	// which at 64KB each covers files up to 64 PB. Big-endian is a convention for binary
	// protocols (most significant byte first) — either endianness would work.
	nonce[7] = byte(counter >> 32)
	nonce[8] = byte(counter >> 24)
	nonce[9] = byte(counter >> 16)
	nonce[10] = byte(counter >> 8)
	nonce[11] = byte(counter)
	return nonce
}
