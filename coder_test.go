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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCoder__Nothing(t *testing.T) {
	data := []byte("hello, world")
	cc := NoEncoding()

	encoded, err := cc.encode(data)
	require.NoError(t, err)
	require.Equal(t, data, encoded)
	data[0] = 'H'
	require.Equal(t, byte('h'), encoded[0])

	data = []byte("hello, world")
	plain, err := cc.decode(encoded)
	require.NoError(t, err)
	require.Equal(t, data, plain)
	encoded[0] = 'X'
	require.Equal(t, byte('h'), plain[0])
}

func TestCoder__Base64(t *testing.T) {
	data := []byte("hello, world")
	cc := Base64()

	encoded, err := cc.encode(data)
	require.NoError(t, err)

	plain, err := cc.decode(encoded)
	require.NoError(t, err)

	require.Equal(t, data, plain)
}
