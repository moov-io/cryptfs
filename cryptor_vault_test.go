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

func TestVaultCryptor(t *testing.T) {
	conf := VaultConfig{
		Address: "http://localhost:8200",
		Token: &TokenConfig{
			Token: "myroot",
		},
		KeyName: "testkey",
	}
	vc, err := NewVaultCryptor(conf)
	require.NoError(t, err)

	fsys, err := New(vc)
	require.NoError(t, err)

	t.Run("basic", func(t *testing.T) {
		testCryptFS(t, fsys)
	})

	t.Run("large input", func(t *testing.T) {
		input := []byte(strings.Repeat("0123456789", 100000))

		path := filepath.Join(t.TempDir(), "data.txt")

		// Write input to a file
		err := fsys.WriteFile(path, input, 0600)
		require.NoError(t, err)

		// Read the decrypted file contents
		bs, err := fsys.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, input, bs)
	})
}