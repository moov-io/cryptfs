package main

import (
	"os"
	"strings"
	"testing"

	"github.com/moov-io/cryptfs"
	"github.com/stretchr/testify/require"
)

func TestCryptfs(t *testing.T) {
	key := []byte(strings.Repeat("1", 16))
	fs, err := cryptfs.FromCryptor(cryptfs.NewAESCryptor(key))
	require.NoError(t, err)

	cleartext := []byte("abcdef")

	fd1, err := os.CreateTemp("", "cryptfs-test-*")
	require.NoError(t, err)
	_, err = fd1.Write(cleartext)
	require.NoError(t, err)
	enc, err := encrypt(fs, fd1.Name())
	require.NoError(t, err)

	fd2, err := os.CreateTemp("", "cryptfs-test-*")
	require.NoError(t, err)
	_, err = fd2.Write(enc)
	require.NoError(t, err)
	dec, err := decrypt(fs, fd2.Name())
	require.NoError(t, err)

	require.Equal(t, string(cleartext), string(dec))
}

func TestCryptfsErr(t *testing.T) {
	key := []byte(strings.Repeat("1", 16))
	fs, err := cryptfs.FromCryptor(cryptfs.NewAESCryptor(key))
	require.NoError(t, err)

	_, err = decrypt(fs, "/does/not/exist")
	require.Error(t, err)

	_, err = encrypt(fs, "/does/not/exist")
	require.Error(t, err)
}
