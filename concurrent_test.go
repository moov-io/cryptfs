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
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConcurrency__AES(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrency test due to -short")
	}

	cc, err := NewAESCryptor([]byte("1234567812345678"))
	require.NoError(t, err)

	parent := t.TempDir()
	filesys, err := New(cc, Base64())
	require.NoError(t, err)

	trials := 1000

	var wg sync.WaitGroup
	wg.Add(trials)
	for i := 0; i < trials; i++ {
		go func() {
			defer wg.Done()

			// Write a file and read it back
			filename, data := setup(parent)

			err := filesys.WriteFile(filename, data, 0600)
			require.NoError(t, err)

			plain, err := filesys.ReadFile(filename)
			require.NoError(t, err)
			require.Equal(t, data, plain)
		}()
	}
	wg.Wait()
}
