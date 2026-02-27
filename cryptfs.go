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
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

type FS struct {
	compressor Compressor
	cryptor    Cryptor
	coder      Coder

	hmacKey     []byte
	keyProvider KeyProvider // nil = streaming not available (GPG-only)
	chunkSize   int         // 0 = DefaultChunkSize
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
		fsys.hmacKey = key
	}
}

// Looking at these changes, I'm not sure that it makes sense to use FS type
// as we technically add keyprovider and constructors for Reader and Writer.
// maybe new type for StreamFS will be better?
func (fsys *FS) SetKeyProvider(kp KeyProvider) {
	if fsys != nil {
		fsys.keyProvider = kp
	}
}

func (fsys *FS) SetChunkSize(size int) {
	if fsys != nil {
		fsys.chunkSize = size
	}
}

// NewWriter returns a streaming encryption writer. Data written to the returned
// Writer is compressed (if configured), encrypted in chunks, and written to dst.
// The caller must call Close on the returned Writer to finalize the stream.
func (fsys *FS) NewWriter(dst io.Writer) (*Writer, error) {
	if fsys.keyProvider == nil {
		return nil, errors.New("no key provider configured; use SetKeyProvider")
	}

	dk, err := fsys.keyProvider.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating data key: %w", err)
	}

	var prefix [noncePrefixSize]byte
	if _, err := rand.Read(prefix[:]); err != nil {
		return nil, fmt.Errorf("generating nonce prefix: %w", err)
	}

	compress := isGzip(fsys.compressor)

	var flags byte
	if compress {
		flags |= flagGzip
	}

	h := &fileHeader{
		Version:     formatVersion,
		Flags:       flags,
		NoncePrefix: prefix,
		WrappedKey:  dk.WrappedKey,
	}

	if err := writeHeader(dst, h); err != nil {
		return nil, fmt.Errorf("writing header: %w", err)
	}

	return newWriter(dst, dk.Plaintext, h, compress, fsys.chunkSize)
}

// NewReader returns a streaming decryption reader. It reads the CRFS header,
// unwraps the data key, and returns a reader that decrypts and decompresses on Read.
// The caller must call Close on the returned Reader.
func (fsys *FS) NewReader(src io.Reader) (*Reader, error) {
	if fsys.keyProvider == nil {
		return nil, errors.New("no key provider configured; use SetKeyProvider")
	}

	h, aad, err := readHeader(src)
	if err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}

	var key []byte
	if len(h.WrappedKey) > 0 {
		key, err = fsys.keyProvider.UnwrapKey(h.WrappedKey)
		if err != nil {
			return nil, fmt.Errorf("unwrapping data key: %w", err)
		}
	} else {
		dk, err := fsys.keyProvider.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("getting key: %w", err)
		}
		key = dk.Plaintext
	}

	compress := h.Flags&flagGzip != 0
	return newReader(src, key, aad, compress)
}

func isGzip(c Compressor) bool {
	_, ok := c.(*gzipCompressor)
	return ok
}

// Open will open a file at the given name
func (fsys *FS) Open(name string) (fs.File, error) {
	fd, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("opening %s failed: %w", name, err)
	}
	return fd, nil
}

// Reveal will decode and then decrypt the bytes its given.
// If the data starts with the CRFS magic header, it is decoded using the
// streaming reader (requires a KeyProvider to be configured).
func (fsys *FS) Reveal(encodedBytes []byte) ([]byte, error) {
	// Auto-detect new CRFS format
	if len(encodedBytes) >= 4 && bytes.Equal(encodedBytes[:4], magic[:]) {
		if fsys.keyProvider == nil {
			return nil, errors.New("CRFS format detected but no key provider configured")
		}
		r, err := fsys.NewReader(bytes.NewReader(encodedBytes))
		if err != nil {
			return nil, fmt.Errorf("creating stream reader: %w", err)
		}
		plaintext, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("reading stream: %w", err)
		}
		if err := r.Close(); err != nil {
			return nil, fmt.Errorf("closing stream reader: %w", err)
		}
		return plaintext, nil
	}

	bs, err := fsys.coder.decode(encodedBytes)
	if err != nil {
		return nil, fmt.Errorf("decoding: %w", err)
	}

	// Verify MAC if hmacKey is set
	if len(fsys.hmacKey) > 1 {
		macSize := sha256.Size
		if len(bs) < macSize {
			return nil, errors.New("data too short to contain valid HMAC")
		}

		receivedMAC := bs[:macSize]
		bs = bs[macSize:]

		expectedMAC := fsys.computeHMAC(bs)
		if !hmac.Equal(receivedMAC, expectedMAC) {
			return nil, errors.New("invalid MAC, data integrity could be compromised")
		}
	}

	bs, err = fsys.cryptor.decrypt(bs)
	if err != nil {
		return nil, fmt.Errorf("decryption: %w", err)
	}

	bs, err = fsys.compressor.decompress(bs)
	if err != nil {
		return nil, fmt.Errorf("decompression: %w", err)
	}
	return bs, nil
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
	bs, err := fsys.compressor.compress(plaintext)
	if err != nil {
		return nil, fmt.Errorf("compression: %w", err)
	}

	bs, err = fsys.cryptor.encrypt(bs)
	if err != nil {
		return nil, fmt.Errorf("encryption: %w", err)
	}

	// Prepend the MAC to the encrypted data
	if len(fsys.hmacKey) > 1 {
		mac := fsys.computeHMAC(bs)
		bs = append(mac, bs...)
	}

	bs, err = fsys.coder.encode(bs)
	if err != nil {
		return nil, fmt.Errorf("encoding: %w", err)
	}

	return bs, nil
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
