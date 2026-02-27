package cryptfs

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHeaderRoundTrip(t *testing.T) {
	t.Run("without wrapped key", func(t *testing.T) {
		var prefix [noncePrefixSize]byte
		_, err := rand.Read(prefix[:])
		require.NoError(t, err)

		h := &fileHeader{
			Version:     formatVersion,
			Flags:       flagGzip,
			NoncePrefix: prefix,
		}

		var buf bytes.Buffer
		err = writeHeader(&buf, h)
		require.NoError(t, err)
		require.Equal(t, fixedHeaderSize, buf.Len())

		got, aad, err := readHeader(&buf)
		require.NoError(t, err)
		require.Equal(t, h.Version, got.Version)
		require.Equal(t, h.Flags, got.Flags)
		require.Equal(t, h.NoncePrefix, got.NoncePrefix)
		require.Empty(t, got.WrappedKey)
		require.Equal(t, fixedHeaderSize, len(aad))
	})

	t.Run("with wrapped key", func(t *testing.T) {
		var prefix [noncePrefixSize]byte
		_, err := rand.Read(prefix[:])
		require.NoError(t, err)

		wrappedKey := []byte("vault:v1:someciphertext==")

		h := &fileHeader{
			Version:     formatVersion,
			Flags:       0x00,
			NoncePrefix: prefix,
			WrappedKey:  wrappedKey,
		}

		var buf bytes.Buffer
		err = writeHeader(&buf, h)
		require.NoError(t, err)
		require.Equal(t, fixedHeaderSize+len(wrappedKey), buf.Len())

		got, aad, err := readHeader(&buf)
		require.NoError(t, err)
		require.Equal(t, h.Version, got.Version)
		require.Equal(t, h.Flags, got.Flags)
		require.Equal(t, h.NoncePrefix, got.NoncePrefix)
		require.Equal(t, wrappedKey, got.WrappedKey)
		require.Equal(t, fixedHeaderSize+len(wrappedKey), len(aad))
	})
}

func TestHeaderBytes(t *testing.T) {
	h := &fileHeader{
		Version: formatVersion,
		Flags:   flagGzip,
	}

	bs := headerBytes(h)
	require.Equal(t, byte('C'), bs[0])
	require.Equal(t, byte('R'), bs[1])
	require.Equal(t, byte('F'), bs[2])
	require.Equal(t, byte('S'), bs[3])
	require.Equal(t, byte(formatVersion), bs[4])
	require.Equal(t, byte(flagGzip), bs[5])
}

func TestReadHeaderErrors(t *testing.T) {
	t.Run("too short", func(t *testing.T) {
		_, _, err := readHeader(bytes.NewReader([]byte("CR")))
		require.Error(t, err)
	})

	t.Run("bad magic", func(t *testing.T) {
		bs := make([]byte, fixedHeaderSize)
		copy(bs[0:4], []byte("XXXX"))
		_, _, err := readHeader(bytes.NewReader(bs))
		require.ErrorContains(t, err, "invalid magic bytes")
	})

	t.Run("bad version", func(t *testing.T) {
		bs := make([]byte, fixedHeaderSize)
		copy(bs[0:4], magic[:])
		bs[4] = 0xFF
		_, _, err := readHeader(bytes.NewReader(bs))
		require.ErrorContains(t, err, "unsupported format version")
	})

	t.Run("truncated wrapped key", func(t *testing.T) {
		bs := make([]byte, fixedHeaderSize)
		copy(bs[0:4], magic[:])
		bs[4] = formatVersion
		// wrapped key length = 100, but no data follows
		bs[13] = 0
		bs[14] = 100
		_, _, err := readHeader(bytes.NewReader(bs))
		require.Error(t, err)
	})
}

func TestBuildNonce(t *testing.T) {
	var prefix [noncePrefixSize]byte
	for i := range prefix {
		prefix[i] = byte(i + 1)
	}

	nonce := buildNonce(prefix, 0)
	require.Equal(t, prefix[:], nonce[:noncePrefixSize])
	require.Equal(t, [5]byte{0, 0, 0, 0, 0}, [5]byte(nonce[7:12]))

	nonce = buildNonce(prefix, 1)
	require.Equal(t, [5]byte{0, 0, 0, 0, 1}, [5]byte(nonce[7:12]))

	nonce = buildNonce(prefix, 0x0102030405)
	require.Equal(t, [5]byte{1, 2, 3, 4, 5}, [5]byte(nonce[7:12]))
}

func TestNonceUniqueness(t *testing.T) {
	var prefix [noncePrefixSize]byte
	_, err := rand.Read(prefix[:])
	require.NoError(t, err)

	seen := make(map[[nonceSize]byte]bool)
	for i := uint64(0); i < 1000; i++ {
		n := buildNonce(prefix, i)
		require.False(t, seen[n], "nonce collision at counter %d", i)
		seen[n] = true
	}
}
