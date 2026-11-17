package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenAESCryptorDoesNotPrintKey(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = w

	validKey := strings.Repeat("1", 16)
	cc, err := openAESCryptor(validKey)
	require.NoError(t, w.Close())
	os.Stdout = old
	require.NoError(t, err)
	require.NotNil(t, cc)

	out, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NotContains(t, string(out), validKey)
	require.NotContains(t, string(out), "data:")
}

func TestAESCryptor(t *testing.T) {
	validKey := strings.Repeat("1", 16)

	// Open an AES cryptor that's in cleartext
	cc, err := openAESCryptor(validKey)
	require.NoError(t, err)
	require.NotNil(t, cc)

	// Open an AES cryptor that's base64 encoded
	base64key := base64.StdEncoding.EncodeToString([]byte(validKey))
	cc, err = openAESCryptor(fmt.Sprintf("base64:%s", base64key))
	require.NoError(t, err)
	require.NotNil(t, cc)

	// Open an AES cryptor that's in a file
	fd, err := os.CreateTemp("", "cryptfs-aes-*")
	require.NoError(t, err)
	_, err = fd.WriteString(validKey)
	require.NoError(t, err)
	cc, err = openAESCryptor(fd.Name())
	require.NoError(t, err)
	require.NotNil(t, cc)
	fd.Close()

	// Open an AES cryptfs that's in a file and base64 encoded
	fd, err = os.CreateTemp("", "cryptfs-aes-*")
	require.NoError(t, err)
	_, err = fd.WriteString(base64key)
	require.NoError(t, err)
	cc, err = openAESCryptor(fd.Name())
	require.NoError(t, err)
	require.NotNil(t, cc)
	fd.Close()
}

func TestAESCryptorErr(t *testing.T) {
	cc, err := openAESCryptor("/does/not/exist")
	require.Error(t, err)
	require.Nil(t, cc)
}
