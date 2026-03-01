package stream

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReaderCorruptionDetection(t *testing.T) {
	key := []byte("1234567890123456")
	original := []byte("sensitive data that must not be tampered with")

	t.Run("tampered ciphertext", func(t *testing.T) {
		buf := writeTestData(t, key, original, false, 0)
		data := buf.Bytes()

		// Find the first chunk data (after header + 4-byte length)
		chunkStart := fixedHeaderSize + 4 + nonceSize
		if chunkStart < len(data) {
			data[chunkStart] ^= 0xFF // flip bits
		}

		r := bytes.NewReader(data)
		_, aad, err := readHeader(r)
		require.NoError(t, err)

		dr, err := newReader(r, key, aad, false)
		require.NoError(t, err)

		_, err = io.ReadAll(dr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "decrypting chunk")
	})

	t.Run("tampered header AAD", func(t *testing.T) {
		buf := writeTestData(t, key, original, false, 0)
		data := buf.Bytes()

		// Tamper with flags byte in the header
		data[5] ^= 0xFF

		r := bytes.NewReader(data)
		_, aad, err := readHeader(r)
		require.NoError(t, err)

		dr, err := newReader(r, key, aad, false)
		require.NoError(t, err)

		_, err = io.ReadAll(dr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "decrypting chunk 0")
	})

	t.Run("wrong key", func(t *testing.T) {
		buf := writeTestData(t, key, original, false, 0)

		wrongKey := []byte("6543210987654321")
		r := bytes.NewReader(buf.Bytes())
		_, aad, err := readHeader(r)
		require.NoError(t, err)

		dr, err := newReader(r, wrongKey, aad, false)
		require.NoError(t, err)

		_, err = io.ReadAll(dr)
		require.Error(t, err)
	})

	t.Run("reordered chunks", func(t *testing.T) {
		buf := writeTestData(t, key, original, false, 10) // small chunks
		data := buf.Bytes()

		// Parse the data to find chunk boundaries and swap two chunks
		offset := fixedHeaderSize
		type chunkData struct {
			length uint32
			data   []byte
		}
		var chunks []chunkData
		for {
			if offset+4 > len(data) {
				break
			}
			length := binary.BigEndian.Uint32(data[offset : offset+4])
			if length == 0 {
				break // end marker
			}
			cd := chunkData{
				length: length,
				data:   make([]byte, length),
			}
			copy(cd.data, data[offset+4:offset+4+int(length)])
			chunks = append(chunks, cd)
			offset += 4 + int(length)
		}

		if len(chunks) < 2 {
			t.Skip("need at least 2 chunks to test reordering")
		}

		// Swap first two chunks
		chunks[0], chunks[1] = chunks[1], chunks[0]

		// Reconstruct
		var reordered bytes.Buffer
		reordered.Write(data[:fixedHeaderSize]) // header
		for _, c := range chunks {
			var lenBuf [4]byte
			binary.BigEndian.PutUint32(lenBuf[:], c.length)
			reordered.Write(lenBuf[:])
			reordered.Write(c.data)
		}
		var endMarker [4]byte
		reordered.Write(endMarker[:])

		r := bytes.NewReader(reordered.Bytes())
		_, aad, err := readHeader(r)
		require.NoError(t, err)

		dr, err := newReader(r, key, aad, false)
		require.NoError(t, err)

		_, err = io.ReadAll(dr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "nonce counter mismatch")
	})

	t.Run("truncated stream", func(t *testing.T) {
		buf := writeTestData(t, key, original, false, 0)
		data := buf.Bytes()

		// Truncate before end marker
		truncated := data[:len(data)-4]

		r := bytes.NewReader(truncated)
		_, aad, err := readHeader(r)
		require.NoError(t, err)

		dr, err := newReader(r, key, aad, false)
		require.NoError(t, err)

		_, err = io.ReadAll(dr)
		require.Error(t, err)
	})
}

func TestReaderUseAfterClose(t *testing.T) {
	key := []byte("1234567890123456")
	kp := NewStaticKeyProvider(key)

	t.Run("Read after Close returns ErrClosed", func(t *testing.T) {
		original := []byte("hello, world")
		var buf bytes.Buffer
		w, err := NewWriter(&buf, kp)
		require.NoError(t, err)
		_, err = w.Write(original)
		require.NoError(t, err)
		require.NoError(t, w.Close())

		r, err := NewReader(bytes.NewReader(buf.Bytes()), kp)
		require.NoError(t, err)
		require.NoError(t, r.Close())

		_, err = r.Read(make([]byte, 10))
		require.ErrorIs(t, err, ErrClosed)
	})

	t.Run("double Close returns ErrClosed", func(t *testing.T) {
		original := []byte("hello, world")
		var buf bytes.Buffer
		w, err := NewWriter(&buf, kp)
		require.NoError(t, err)
		_, err = w.Write(original)
		require.NoError(t, err)
		require.NoError(t, w.Close())

		r, err := NewReader(bytes.NewReader(buf.Bytes()), kp)
		require.NoError(t, err)
		require.NoError(t, r.Close())
		require.ErrorIs(t, r.Close(), ErrClosed)
	})

	t.Run("sticky error after read failure", func(t *testing.T) {
		key := []byte("1234567890123456")
		original := []byte("data for sticky error test")

		buf := writeTestData(t, key, original, false, 0)
		data := buf.Bytes()

		// Tamper with ciphertext to cause a decryption failure
		chunkStart := fixedHeaderSize + 4 + nonceSize
		data[chunkStart] ^= 0xFF

		r := bytes.NewReader(data)
		_, aad, err := readHeader(r)
		require.NoError(t, err)

		dr, err := newReader(r, key, aad, false)
		require.NoError(t, err)

		// First read fails with decryption error
		_, firstErr := dr.Read(make([]byte, 256))
		require.Error(t, firstErr)
		require.Contains(t, firstErr.Error(), "decrypting chunk")

		// Second read returns the same sticky error
		_, secondErr := dr.Read(make([]byte, 256))
		require.Equal(t, firstErr, secondErr)
	})
}

func TestReaderSmallReads(t *testing.T) {
	key := []byte("1234567890123456")
	original := []byte("The quick brown fox jumps over the lazy dog")

	buf := writeTestData(t, key, original, false, 10)

	r := bytes.NewReader(buf.Bytes())
	_, aad, err := readHeader(r)
	require.NoError(t, err)

	dr, err := newReader(r, key, aad, false)
	require.NoError(t, err)

	// Read one byte at a time
	var result []byte
	p := make([]byte, 1)
	for {
		n, err := dr.Read(p)
		if n > 0 {
			result = append(result, p[:n]...)
		}
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}
	require.Equal(t, original, result)
}

func TestReaderAESKeySize(t *testing.T) {
	for _, keySize := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("AES-%d", keySize*8), func(t *testing.T) {
			key := make([]byte, keySize)
			_, err := rand.Read(key)
			require.NoError(t, err)

			original := []byte("test data for various key sizes")
			buf := writeTestData(t, key, original, false, 0)

			got := readTestData(t, key, buf.Bytes())
			require.Equal(t, original, got)
		})
	}
}
