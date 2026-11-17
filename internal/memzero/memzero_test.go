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

package memzero

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBytes(t *testing.T) {
	b := bytes.Repeat([]byte{0xA5}, 24)
	Bytes(b)
	require.Equal(t, make([]byte, 24), b)

	b = bytes.Repeat([]byte{0xA5}, 16)
	Bytes(b[4:8])
	require.Equal(t, []byte{0xA5, 0xA5, 0xA5, 0xA5, 0, 0, 0, 0}, b[:8])
	require.Equal(t, bytes.Repeat([]byte{0xA5}, 8), b[8:])

	Bytes(nil)
	Bytes([]byte{})
}

func TestClone(t *testing.T) {
	require.Nil(t, Clone(nil))

	in := []byte{1, 2, 3}
	out := Clone(in)
	require.Equal(t, in, out)
	in[0] = 9
	require.Equal(t, byte(1), out[0])
}
