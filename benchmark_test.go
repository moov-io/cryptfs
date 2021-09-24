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
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func init() {
	rand.Seed(time.Now().Unix())
}

func BenchmarkCryptfs__AES(b *testing.B) {
	cc, err := NewAESCryptor([]byte("1234567812345678"))
	require.NoError(b, err)

	parent := b.TempDir()
	filesys, err := New(cc)
	require.NoError(b, err)
	filesys.SetCoder(Base64())

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Write a file and read it back
		filename, data := setup(parent)

		err := filesys.WriteFile(filename, data, 0600)
		require.NoError(b, err)

		plain, err := filesys.ReadFile(filename)
		require.NoError(b, err)
		require.Equal(b, data, plain)
	}
}

func setup(parent string) (string, []byte) {
	filename := filepath.Join(parent, fmt.Sprintf("%s.txt", randString(12)))
	return filename, []byte(randString(100))
}

func randString(length int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	out := make([]rune, length)
	for i := range out {
		out[i] = letters[rand.Intn(len(letters))] //nolint:gosec
	}
	return string(out)
}
