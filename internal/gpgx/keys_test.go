// Copyright 2020 The Moov Authors
// Use of this source code is governed by an Apache License
// license that can be found in the LICENSE file.

package gpgx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	password = []byte("password")

	privateKeyPath = filepath.Join("testdata", "key.priv")
	publicKeyPath  = filepath.Join("testdata", "key.pub")
)

func TestGPG(t *testing.T) {
	// Encrypt
	pubKey, err := ReadArmoredKeyFile(publicKeyPath)
	require.NoError(t, err)
	msg, err := Encrypt([]byte("hello, world"), pubKey)
	require.NoError(t, err)
	if len(msg) == 0 {
		t.Error("empty encrypted message")
	}

	// Decrypt
	privKey, err := ReadPrivateKeyFile(privateKeyPath, password)
	require.NoError(t, err)
	out, err := Decrypt(msg, privKey)
	require.NoError(t, err)
	require.Equal(t, "hello, world", string(out))

	// Decrypt
	fd, err := os.Open(privateKeyPath)
	require.NoError(t, err)
	privKey, err = ReadPrivateKey(fd, password)
	require.NoError(t, err)
	out, err = Decrypt(msg, privKey)
	require.NoError(t, err)
	require.Equal(t, "hello, world", string(out))
}

func TestGPGError(t *testing.T) {
	el, err := ReadArmoredKey(strings.NewReader("invalid"))
	require.Error(t, err)
	require.Empty(t, el)

	el, err = ReadArmoredKeyFile("invalid-path")
	require.Error(t, err)
	require.Empty(t, el)

	el, err = ReadPrivateKey(strings.NewReader("invalid"), []byte("password"))
	require.Error(t, err)
	require.Empty(t, el)

	el, err = ReadPrivateKeyFile("invalid-path", []byte("password"))
	require.Error(t, err)
	require.Empty(t, el)
}

func TestGPG__readMessageError(t *testing.T) {
	bs, err := readMessage([]byte("invalid"), nil)
	require.Error(t, err)
	require.Empty(t, bs)
}
