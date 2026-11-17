package stream

import (
	"bytes"
	"io"
	"testing"

	"github.com/moov-io/cryptfs/internal/memzero"
	"github.com/stretchr/testify/require"
)

func TestWriterCloseClearsPlaintextBuffer(t *testing.T) {
	key := []byte("1234567890123456")
	var buf bytes.Buffer
	w, err := NewWriter(&buf, NewStaticKeyProvider(key), WithChunkSize(64))
	require.NoError(t, err)

	_, err = w.Write([]byte("hello, world leftover plaintext"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	require.Equal(t, make([]byte, cap(w.chunks.buf)), w.chunks.buf[:cap(w.chunks.buf)])
}

func TestReaderCloseClearsPlaintextBuffer(t *testing.T) {
	key := []byte("1234567890123456")
	var buf bytes.Buffer
	w, err := NewWriter(&buf, NewStaticKeyProvider(key), WithChunkSize(64))
	require.NoError(t, err)
	_, err = w.Write(bytes.Repeat([]byte("x"), 40))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	r, err := NewReader(bytes.NewReader(buf.Bytes()), NewStaticKeyProvider(key))
	require.NoError(t, err)

	one := make([]byte, 1)
	_, err = r.Read(one)
	require.NoError(t, err)
	require.Greater(t, cap(r.chunks.buf), 0)

	require.NoError(t, r.Close())
	require.Nil(t, r.chunks.buf)
}

func TestStaticKeyProvider_GenerateKeyCopyCanBeWiped(t *testing.T) {
	key := []byte("abcdefghijklmnop")
	kp := NewStaticKeyProvider(key)

	dk, err := kp.GenerateKey()
	require.NoError(t, err)
	memzero.Bytes(dk.Plaintext)

	dk2, err := kp.GenerateKey()
	require.NoError(t, err)
	require.Equal(t, key, dk2.Plaintext)

	unwrapped, err := kp.UnwrapKey(nil)
	require.NoError(t, err)
	memzero.Bytes(unwrapped)
	unwrapped2, err := kp.UnwrapKey(nil)
	require.NoError(t, err)
	require.Equal(t, key, unwrapped2)
}

func TestWriterDoesNotWipeCallerKey(t *testing.T) {
	key := []byte("1234567890123456")
	var buf bytes.Buffer
	w, err := NewWriter(&buf, NewStaticKeyProvider(key))
	require.NoError(t, err)
	_, err = w.Write([]byte("hi"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.Equal(t, []byte("1234567890123456"), key)

	r, err := NewReader(bytes.NewReader(buf.Bytes()), NewStaticKeyProvider(key))
	require.NoError(t, err)
	_, err = io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())
	require.Equal(t, []byte("1234567890123456"), key)
}
