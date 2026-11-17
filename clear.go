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

// Clear overwrites every byte of b with zero, for a caller clearing a key or
// plaintext they own.
//
// Prefer it to the clear builtin. A clear(b) with no later read of b is a dead
// store the compiler may remove; Clear is not inlined and keeps b reachable
// until the write is done, so the write happens.
//
// cryptfs copies keys you pass in (AES, HMAC, stream static keys, GPG
// password). Clearing your slice after NewAESCryptor, SetHMACKey, or
// NewStaticKeyProvider does not affect the FS. Call Clear on buffers you own
// when you are done with them.
//
// Clear zeroes len(b) bytes. To clear a slice's full backing array, pass
// b[:cap(b)]. It is best-effort heap hygiene: it does not reach copies in CPU
// registers or on the stack, key schedules held by crypto/cipher, or strings.
func Clear(b []byte) {
	memzero.Bytes(b)
}
