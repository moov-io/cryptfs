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
	"compress/gzip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGzip(t *testing.T) {
	gz := Gzip()
	plain := []byte("hello, world")
	compressed, err := gz.compress(plain)
	require.NoError(t, err)

	t.Run("not compressed equals compressed", func(t *testing.T) {
		decompressed, err := gz.decompress(plain)
		require.NoError(t, err)
		require.Equal(t, plain, decompressed)
	})

	t.Run("compressed can be decompressed", func(t *testing.T) {
		decompressed, err := gz.decompress(compressed)
		require.NoError(t, err)
		require.Equal(t, plain, decompressed)
	})

	t.Run("empty", func(t *testing.T) {
		out, err := gz.compress(nil)
		require.NoError(t, err)

		out, err = gz.decompress(out)
		require.NoError(t, err)
		require.Len(t, out, 0)

		require.Equal(t, "", string(out))

		// nil input
		out, err = gz.decompress(nil)
		require.NoError(t, err)
		require.Len(t, out, 0)

		require.Equal(t, "", string(out))
	})
}

func TestGzipLevel(t *testing.T) {
	gz := GzipLevel(gzip.BestCompression)
	plain := []byte("hello, world")
	compressed, err := gz.compress(plain)
	require.NoError(t, err)

	t.Run("not compressed equals compressed", func(t *testing.T) {
		decompressed, err := gz.decompress(plain)
		require.NoError(t, err)
		require.Equal(t, plain, decompressed)
	})

	t.Run("compressed can be decompressed", func(t *testing.T) {
		decompressed, err := gz.decompress(compressed)
		require.NoError(t, err)
		require.Equal(t, plain, decompressed)
	})
}

func TestGzipRequired(t *testing.T) {
	gz := GzipRequired(gzip.BestSpeed)
	plain := []byte("hello, world")
	compressed, err := gz.compress(plain)
	require.NoError(t, err)

	t.Run("not compressed is rejected", func(t *testing.T) {
		decompressed, err := gz.decompress(plain)
		require.ErrorIs(t, err, gzip.ErrHeader)
		require.Nil(t, decompressed)
	})

	t.Run("compressed can be decompressed", func(t *testing.T) {
		decompressed, err := gz.decompress(compressed)
		require.NoError(t, err)
		require.Equal(t, plain, decompressed)
	})
}
