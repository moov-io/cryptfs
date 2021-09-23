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
	"encoding/base64"
)

type Coder interface {
	Encode(data []byte) ([]byte, error)
	Decode(data []byte) ([]byte, error)
}

type base64Coder struct{}

func Base64() Coder {
	return &base64Coder{}
}

func (c *base64Coder) Encode(data []byte) ([]byte, error) {
	ebuf := make([]byte, base64.RawStdEncoding.EncodedLen(len(data)))
	base64.RawStdEncoding.Encode(ebuf, data)
	return ebuf, nil
}

func (c *base64Coder) Decode(data []byte) ([]byte, error) {
	dbuf := make([]byte, base64.RawStdEncoding.DecodedLen(len(data)))
	base64.RawStdEncoding.Decode(dbuf, data)
	return dbuf, nil
}
