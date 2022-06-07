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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCryptorGPG(t *testing.T) {
	ee, err := NewGPGEncryptorFile(filepath.Join("internal", "gpgx", "testdata", "key.pub"))
	require.NoError(t, err)

	dd, err := NewGPGDecryptorFile(filepath.Join("internal", "gpgx", "testdata", "key.priv"), []byte("password"))
	require.NoError(t, err)

	enc, err := ee.encrypt([]byte("hello, world"))
	require.NoError(t, err)

	dec1, err := dd.decrypt(enc)
	require.NoError(t, err)
	require.Equal(t, "hello, world", string(dec1))

	dec2, err := dd.decrypt(enc)
	require.NoError(t, err)
	require.Equal(t, "hello, world", string(dec2))
}

func TestCryptorGPGError(t *testing.T) {
	ee, err := NewGPGEncryptorFile("invalid-path")
	require.Error(t, err)
	require.Nil(t, ee)

	ee = &GPGCryptor{}
	bs, err := ee.encrypt([]byte("hello, world"))
	require.Error(t, err)
	require.Len(t, bs, 0)

	dd, err := NewGPGDecryptorFile("invalid-path", []byte("password"))
	require.Error(t, err)
	require.Nil(t, ee)

	dd = &GPGCryptor{}
	bs, err = dd.decrypt([]byte("hello, world"))
	require.Error(t, err)
	require.Len(t, bs, 0)
}
