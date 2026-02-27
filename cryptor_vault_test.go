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
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/moov-io/cryptfs/stream"

	"github.com/stretchr/testify/require"
)

func TestVaultCryptor(t *testing.T) {
	shouldSkipDockerTest(t)

	if testing.Short() {
		t.Skip("skipping network tests")
	}

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
		input := []byte(strings.Repeat("0123456789", 50_000))

		path := filepath.Join(t.TempDir(), "data.txt")

		// Write input to a file
		err := fsys.WriteFile(path, input, 0600)
		require.NoError(t, err)

		// Read the decrypted file contents
		bs, err := fsys.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, input, bs)
	})

	t.Run("with HMAC key", func(t *testing.T) {
		fsys.SetHMACKey([]byte(strings.Repeat("abcdef", 10)))

		testCryptFS(t, fsys)
	})
}

func TestVaultDataKey(t *testing.T) {
	shouldSkipDockerTest(t)

	conf := VaultConfig{
		Address: "http://localhost:8200",
		Token:   &TokenConfig{Token: "myroot"},
		KeyName: "testkey",
	}

	kp, err := NewVaultKeyProvider(conf)
	require.NoError(t, err)

	// Generate a data key
	dk, err := kp.GenerateKey()
	require.NoError(t, err)
	require.Len(t, dk.Plaintext, 32, "Vault default data key is 256-bit")
	require.NotEmpty(t, dk.WrappedKey, "wrapped key should be non-empty")

	// Unwrap it back
	recovered, err := kp.UnwrapKey(dk.WrappedKey)
	require.NoError(t, err)
	require.Equal(t, dk.Plaintext, recovered, "unwrapped key must match original")

	// Full streaming round-trip with Vault envelope encryption
	original := []byte("sensitive data for vault envelope test")

	var buf bytes.Buffer
	w, err := stream.NewWriter(&buf, kp, stream.WithCompression())
	require.NoError(t, err)
	_, err = w.Write(original)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	r, err := stream.NewReader(bytes.NewReader(buf.Bytes()), kp)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.NoError(t, r.Close())

	require.Equal(t, original, got)
}

// how is that that docker is not supported? we run make setup in our tests - and it starts vault in a docker container
func shouldSkipDockerTest(t *testing.T) {
	t.Helper()

	if testing.Short() {
		t.Skip("-short flag specified")
	}

	isGithubCI := os.Getenv("GITHUB_ACTIONS") != ""
	isLinux := runtime.GOOS == "linux"
	if isGithubCI && !isLinux {
		t.Skipf("docker is not supported on %s github runners", runtime.GOOS)
	}
}
