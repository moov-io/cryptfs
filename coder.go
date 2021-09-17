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

package cryptofs

type Coder interface {
	Encode(data []byte) ([]byte, error)
	Decode(data []byte) ([]byte, error)
}

type base64 struct{}

func Base64() Coder {
	return &base64{}
}

// TODO(adam):
// func Base64URL() Coder {
// 	return &base64{}
// }

func (c *base64) Encode(data []byte) ([]byte, error) {
	return data, nil
}

func (c *base64) Decode(data []byte) ([]byte, error) {
	return data, nil
}
