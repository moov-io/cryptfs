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

func TestCryptfsAES(t *testing.T) {
	key := []byte(strings.Repeat("1", 16))
	cc, err := NewAESCryptor(key)
	require.NoError(t, err)
	testCryptfs(t, cc)
}

func testCryptfs(t *testing.T, cryptor Cryptor) {
	t.Helper()

	parent := t.TempDir()
	filesys, err := New(cryptor, Base64())
	require.NoError(t, err)

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
