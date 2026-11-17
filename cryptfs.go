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
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/moov-io/cryptfs/internal/memzero"
)

type FS struct {
	compressor Compressor
	cryptor    Cryptor
	coder      Coder

	hmacKey []byte
}

// New returns a FS instance with the specified Cryptor used for all operations.
//
// Note: The defaults are to use no compression and no encryption.
func New(cryptor Cryptor) (*FS, error) {
	if cryptor == nil {
		return nil, errors.New("nil Cryptor")
	}
	return &FS{
		compressor: NoCompression(),
		cryptor:    cryptor,
		coder:      NoEncoding(),
	}, nil
}

// FromCryptor returns an FS instance and allows passing the results of creating a
// Cryptor directly as the arguments.
func FromCryptor(cryptor Cryptor, err error) (*FS, error) {
	if err != nil {
		return nil, err
	}
	return New(cryptor)
}

func (fsys *FS) SetCompression(compressor Compressor) {
	if fsys != nil && compressor != nil {
		fsys.compressor = compressor
	}
}

func (fsys *FS) SetCoder(coder Coder) {
	if fsys != nil && coder != nil {
		fsys.coder = coder
	}
}

func (fsys *FS) SetHMACKey(key []byte) {
	if fsys != nil {
		fsys.hmacKey = memzero.Clone(key)
	}
}

// Open opens the named file on the local filesystem.
// It does not decrypt. The returned file is the stored bytes (ciphertext if
// the file was written with WriteFile). Use ReadFile or Reveal to decrypt.
func (fsys *FS) Open(name string) (fs.File, error) {
	fd, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("opening %s failed: %w", name, err)
	}
	return fd, nil
}

// Reveal will decode and then decrypt the bytes its given.
func (fsys *FS) Reveal(encodedBytes []byte) ([]byte, error) {
	decoded, err := fsys.coder.decode(encodedBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding: %w", err)
	}

	payload := decoded
	if len(fsys.hmacKey) > 0 {
		macSize := sha256.Size
		if len(decoded) < macSize {
			wipeIfDistinct(decoded, encodedBytes)
			return nil, errors.New("data too short to contain valid HMAC")
		}

		receivedMAC := decoded[:macSize]
		payload = decoded[macSize:]

		expectedMAC := fsys.computeHMAC(payload)
		if !hmac.Equal(receivedMAC, expectedMAC) {
			wipeIfDistinct(decoded, encodedBytes)
			return nil, errors.New("invalid MAC, data integrity could be compromised")
		}
	}

	plain, err := fsys.cryptor.decrypt(payload)
	wipeIfDistinct(decoded, encodedBytes, plain)
	if err != nil {
		wipeIfDistinct(plain)
		return nil, fmt.Errorf("decryption: %w", err)
	}

	out, err := fsys.compressor.decompress(plain)
	wipeIfDistinct(plain, out)
	if err != nil {
		wipeIfDistinct(out)
		return nil, fmt.Errorf("decompression: %w", err)
	}
	return out, nil
}

// ReadFile will attempt to open, decode, and decrypt a file.
func (fsys *FS) ReadFile(name string) ([]byte, error) {
	encodedBytes, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	bs, err := fsys.Reveal(encodedBytes)
	if err != nil {
		return nil, fmt.Errorf("reading %s failed: %w", name, err)
	}
	return bs, nil
}

// Disfigure will encrypt and encode the plaintext
func (fsys *FS) Disfigure(plaintext []byte) ([]byte, error) {
	compressed, err := fsys.compressor.compress(plaintext)
	if err != nil {
		return nil, fmt.Errorf("compression: %w", err)
	}

	encrypted, err := fsys.cryptor.encrypt(compressed)
	wipeIfDistinct(compressed, plaintext, encrypted)
	if err != nil {
		wipeIfDistinct(encrypted, plaintext)
		return nil, fmt.Errorf("encryption: %w", err)
	}

	payload := encrypted
	if len(fsys.hmacKey) > 0 {
		mac := fsys.computeHMAC(encrypted)
		payload = append(mac, encrypted...)
	}

	encoded, err := fsys.coder.encode(payload)
	if len(fsys.hmacKey) > 0 {
		wipeIfDistinct(payload, encoded, encrypted)
	}
	wipeIfDistinct(encrypted, plaintext, encoded)
	if err != nil {
		wipeIfDistinct(encoded, plaintext)
		return nil, fmt.Errorf("encoding: %w", err)
	}

	return encoded, nil
}

func (fsys *FS) computeHMAC(data []byte) []byte {
	mac := hmac.New(sha256.New, fsys.hmacKey)
	mac.Write(data)
	return mac.Sum(nil)
}

// WriteFile will attempt to encrypt, encode, and create a file under the given filepath.
func (fsys *FS) WriteFile(filepath string, plaintext []byte, perm fs.FileMode) error {
	encodedBytes, err := fsys.Disfigure(plaintext)
	if err != nil {
		return err
	}
	err = os.WriteFile(filepath, encodedBytes, perm)
	if err != nil {
		return fmt.Errorf("writing %s failed: %w", filepath, err)
	}
	return nil
}

var _ fs.FS = (&FS{})
var _ fs.ReadFileFS = (&FS{})
