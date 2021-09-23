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
	"io/ioutil"
	"os"
)

type FS struct {
	cryptor Cryptor
	coder   Coder
}

func New(cryptor Cryptor, coder Coder) (*FS, error) {
	if cryptor == nil {
		return nil, errors.New("nil Cryptor")
	}
	if coder == nil {
		return nil, errors.New("nil Coder")
	}
	return &FS{
		cryptor: cryptor,
		coder:   coder,
	}, nil
}

func (fsys *FS) Open(name string) (fs.File, error) {
	return os.Open(name)
}

func (fsys *FS) ReadFile(name string) ([]byte, error) {
	encodedBytes, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	decodedBytes, err := fsys.coder.Decode(encodedBytes)
	if err != nil {
		return nil, err
	}
	plain, err := fsys.cryptor.Decrypt(decodedBytes)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func (fsys *FS) WriteFile(filename string, plaintext []byte, perm fs.FileMode) error {
	encryptedBytes, err := fsys.cryptor.Encrypt(plaintext)
	if err != nil {
		return err
	}
	encodedBytes, err := fsys.coder.Encode(encryptedBytes)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, encodedBytes, perm)
}

var _ fs.FS = (&FS{})
var _ fs.ReadFileFS = (&FS{})
