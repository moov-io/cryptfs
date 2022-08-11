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
	"errors"
	"io/fs"
	"os"
)

type FS struct {
	cryptor Cryptor
	coder   Coder
}

// New returns a FS instance with the specified Cryptor used for all operations.
func New(cryptor Cryptor) (*FS, error) {
	if cryptor == nil {
		return nil, errors.New("nil Cryptor")
	}
	return &FS{
		cryptor: cryptor,
		coder:   NoEncoding(),
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

func (fsys *FS) SetCoder(coder Coder) {
	if fsys != nil && coder != nil {
		fsys.coder = coder
	}
}

func (fsys *FS) Open(name string) (fs.File, error) {
	return os.Open(name)
}

// Reveal will decode and then decrypt the bytes its given
func (fsys *FS) Reveal(encodedBytes []byte) ([]byte, error) {
	decodedBytes, err := fsys.coder.decode(encodedBytes)
	if err != nil {
		return nil, err
	}
	plain, err := fsys.cryptor.decrypt(decodedBytes)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// ReadFile will attempt to open, decode, and decrypt a file.
func (fsys *FS) ReadFile(name string) ([]byte, error) {
	encodedBytes, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return fsys.Reveal(encodedBytes)
}

func (fsys *FS) Disfigure(plaintext []byte) ([]byte, error) {
	encryptedBytes, err := fsys.cryptor.encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	encodedBytes, err := fsys.coder.encode(encryptedBytes)
	if err != nil {
		return nil, err
	}
	return encodedBytes, nil
}

// WriteFile will attempt to encrypt, encode, and create a file under the given filepath.
func (fsys *FS) WriteFile(filepath string, plaintext []byte, perm fs.FileMode) error {
	encodedBytes, err := fsys.Disfigure(plaintext)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, encodedBytes, perm)
}

var _ fs.FS = (&FS{})
var _ fs.ReadFileFS = (&FS{})
