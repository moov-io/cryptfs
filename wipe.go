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

import "github.com/moov-io/cryptfs/internal/memzero"

// wipeIfDistinct overwrites buf, including unused cap, unless buf shares
// backing storage with any keep slice (caller input or a value we still return).
func wipeIfDistinct(buf []byte, keep ...[]byte) {
	if cap(buf) == 0 {
		return
	}
	if len(buf) > 0 {
		for _, k := range keep {
			if len(k) > 0 && &buf[0] == &k[0] {
				return
			}
		}
	}
	memzero.Bytes(buf[:cap(buf)])
}
