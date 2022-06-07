// Licensed to The Moov Authors under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. The Moov Authors licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package cryptfs

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCryptfsEmpty(t *testing.T) {
	fsys, err := New(nil)
	require.Nil(t, fsys)
	require.NotNil(t, err)

	fsys, err = FromCryptor(nil, nil)
	require.Nil(t, fsys)
	require.NotNil(t, err)

	crypt, err := NewAESCryptor([]byte(strings.Repeat("1", 16)))
	require.NoError(t, err)

	fsys, err = New(crypt)
	require.NotNil(t, fsys)
	require.NoError(t, err)
}

func TestCryptfsAES(t *testing.T) {
	key := []byte(strings.Repeat("1", 16))
	cc, err := NewAESCryptor(key)
	require.NoError(t, err)
	testCryptfs(t, cc)
}

func TestCryptGPG(t *testing.T) {
	dir := filepath.Join("internal", "gpgx", "testdata")
	cc, err := NewGPGCryptorFile(
		filepath.Join(dir, "key.pub"),
		filepath.Join(dir, "key.priv"),
		[]byte("password"),
	)
	require.NoError(t, err)
	testCryptfs(t, cc)
}

func TestCryptGPG2(t *testing.T) {
	dir := filepath.Join("internal", "gpgx", "testdata")

	pubKey, err := os.Open(filepath.Join(dir, "key.pub"))
	require.NoError(t, err)

	privKey, err := os.Open(filepath.Join(dir, "key.priv"))
	require.NoError(t, err)

	cc, err := NewGPGCryptor(pubKey, privKey, []byte("password"))
	require.NoError(t, err)
	testCryptfs(t, cc)
}

func testCryptfs(t *testing.T, cryptor Cryptor) {
	t.Helper()

	parent := t.TempDir()
	filesys, err := New(cryptor)
	require.NoError(t, err)
	filesys.SetCoder(Base64())

	// Verify error when file isn't there
	file, err := filesys.Open(filepath.Join(parent, "foo.txt"))
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Nil(t, file)

	// Write a file and verify the encrypted contents
	path := filepath.Join(parent, "bar.txt")

	err = filesys.WriteFile(path, []byte("hello, world"), 0600)
	require.NoError(t, err)

	// Verify there's something written
	bs, _ := ioutil.ReadFile(path)
	require.Greater(t, len(bs), 1)

	// Read the decrypted file contents
	bs, err = filesys.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "hello, world", string(bs))
}

func TestCryptfsError(t *testing.T) {
	parent := t.TempDir()

	cc, err := NewAESCryptor([]byte(strings.Repeat("1", 16)))
	require.NoError(t, err)

	filesys, err := New(cc)
	require.NoError(t, err)
	filesys.SetCoder(Base64())

	badPath := filepath.Join(parent, "missing", "file.txt")

	file, err := filesys.ReadFile(badPath)
	require.Nil(t, file)
	require.ErrorIs(t, err, os.ErrNotExist)

	err = filesys.WriteFile(badPath, []byte("data"), 0600)
	require.ErrorIs(t, err, os.ErrNotExist)
}
