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
	"fmt"
)

// Coder is an interface describing two operations which transform data into
// another format. This can be done to compress or disfigure bytes.
type Coder interface {
	encode(data []byte) ([]byte, error)
	decode(data []byte) ([]byte, error)
}

// NoEncoding is a Coder which does not transform data.
func NoEncoding() Coder {
	return &nothingCoder{}
}

type nothingCoder struct{}

func (*nothingCoder) encode(data []byte) ([]byte, error) {
	return data, nil
}

func (*nothingCoder) decode(data []byte) ([]byte, error) {
	return data, nil
}

// Base64 is a Coder which transforms data following RFC 4648 section 3.2.
// There are no padding characters added or accepted by this Coder.
func Base64() Coder {
	return &base64Coder{}
}

type base64Coder struct{}

func (c *base64Coder) encode(data []byte) ([]byte, error) {
	ebuf := make([]byte, base64.RawStdEncoding.EncodedLen(len(data)))
	base64.RawStdEncoding.Encode(ebuf, data)
	return ebuf, nil
}

func (c *base64Coder) decode(data []byte) ([]byte, error) {
	dbuf := make([]byte, base64.RawStdEncoding.DecodedLen(len(data)))
	_, err := base64.RawStdEncoding.Decode(dbuf, data)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return dbuf, nil
}
