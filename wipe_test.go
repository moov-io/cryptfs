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
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetHMACKeyCopies(t *testing.T) {
	cc, err := NewAESCryptor([]byte(strings.Repeat("1", 16)))
	require.NoError(t, err)
	fsys, err := New(cc)
	require.NoError(t, err)

	key := []byte("hmac-secret-key!!")
	fsys.SetHMACKey(key)
	key[0] = 'X'

	enc, err := fsys.Disfigure([]byte("hello"))
	require.NoError(t, err)
	plain, err := fsys.Reveal(enc)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), plain)
}

func TestHMACOneByteKeyIsUsed(t *testing.T) {
	cc, err := NewAESCryptor([]byte(strings.Repeat("1", 16)))
	require.NoError(t, err)
	fsys, err := New(cc)
	require.NoError(t, err)
	fsys.SetHMACKey([]byte{0x42})

	enc, err := fsys.Disfigure([]byte("hello"))
	require.NoError(t, err)
	enc[0] ^= 0xFF
	_, err = fsys.Reveal(enc)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid MAC")
}

func TestNoOpCopiesInput(t *testing.T) {
	in := []byte("hello, world")

	enc, err := NoEncryption().encrypt(in)
	require.NoError(t, err)
	require.Equal(t, in, enc)
	in[0] = 'H'
	require.Equal(t, byte('h'), enc[0])

	in = []byte("hello, world")
	out, err := NoEncoding().encode(in)
	require.NoError(t, err)
	in[0] = 'H'
	require.Equal(t, byte('h'), out[0])

	in = []byte("hello, world")
	out, err = NoCompression().compress(in)
	require.NoError(t, err)
	in[0] = 'H'
	require.Equal(t, byte('h'), out[0])
}

func TestGPGPasswordNotMutated(t *testing.T) {
	pass := []byte("password")
	_, err := NewGPGDecryptorFile(filepath.Join("internal", "gpgx", "testdata", "key.priv"), pass)
	require.NoError(t, err)
	require.Equal(t, []byte("password"), pass)
}

func TestSignedByKnownKey(t *testing.T) {
	require.False(t, signedByKnownKey(nil, nil))
}
