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

// Package memzero clears buffers that held key material or plaintext.
//
// cryptfs copies keys it is given, then clears those copies when they are no
// longer needed. It does not modify caller-owned slices (for example a key
// stored on a struct).
//
// What this does and does not guarantee: it overwrites the buffer it is given.
// It cannot reach copies made elsewhere, such as the expanded key schedule
// inside a crypto/cipher.Block, an HMAC's padded keys, or a string.
package memzero

import "runtime"

// Bytes overwrites every byte of b with zero.
//
// It is not inlined, and keeps b reachable until the write is done, so the
// compiler cannot treat the clear as a dead store to a buffer that is about to
// go out of scope.
//
// This is best-effort heap hygiene. It zeroes len(b) bytes only, so a caller
// that wants a slice's whole backing array cleared passes b[:cap(b)]. It does
// not reach copies of the data in CPU registers or on goroutine stacks. A host
// that needs those erased too can wrap its calls into this library in
// runtime/secret.Do; that package is experimental, needs
// GOEXPERIMENT=runtimesecret, and erases registers and stacks only on
// linux/amd64 and linux/arm64 (elsewhere Do just calls its function).
//
//go:noinline
func Bytes(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// Clone returns a new slice with the same contents as in.
// A nil input returns nil.
func Clone(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
