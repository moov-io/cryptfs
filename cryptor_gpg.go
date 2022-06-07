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
	"io"

	"github.com/moov-io/cryptfs/internal/gpgx"

	"github.com/ProtonMail/go-crypto/openpgp"
)

type GPGCryptor struct {
	publicKeys  openpgp.EntityList
	privateKeys openpgp.EntityList
}

func NewGPGDecryptor(data io.Reader, password []byte) (Cryptor, error) {
	privKeys, err := gpgx.ReadPrivateKey(data, password)
	if err != nil {
		return nil, err
	}
	return &GPGCryptor{
		privateKeys: privKeys,
	}, nil
}

func NewGPGDecryptorFile(path string, password []byte) (Cryptor, error) {
	privKeys, err := gpgx.ReadPrivateKeyFile(path, password)
	if err != nil {
		return nil, err
	}
	return &GPGCryptor{
		privateKeys: privKeys,
	}, nil
}

func NewGPGEncryptor(data io.Reader) (Cryptor, error) {
	pubKeys, err := gpgx.ReadArmoredKey(data)
	if err != nil {
		return nil, err
	}
	return &GPGCryptor{
		publicKeys: pubKeys,
	}, nil
}

func NewGPGEncryptorFile(path string) (Cryptor, error) {
	pubKeys, err := gpgx.ReadArmoredKeyFile(path)
	if err != nil {
		return nil, err
	}
	return &GPGCryptor{
		publicKeys: pubKeys,
	}, nil
}

func NewGPGCryptor(publicKey, privateKey io.Reader, password []byte) (Cryptor, error) {
	pubKey, err := gpgx.ReadArmoredKey(publicKey)
	if err != nil {
		return nil, err
	}
	privKey, err := gpgx.ReadPrivateKey(privateKey, password)
	if err != nil {
		return nil, err
	}
	return &GPGCryptor{
		publicKeys:  pubKey,
		privateKeys: privKey,
	}, nil
}

func NewGPGCryptorFile(publicKeyPath, privateKeyPath string, password []byte) (Cryptor, error) {
	pubKey, err := gpgx.ReadArmoredKeyFile(publicKeyPath)
	if err != nil {
		return nil, err
	}
	privKey, err := gpgx.ReadPrivateKeyFile(privateKeyPath, password)
	if err != nil {
		return nil, err
	}
	return &GPGCryptor{
		publicKeys:  pubKey,
		privateKeys: privKey,
	}, nil
}

func (c *GPGCryptor) encrypt(data []byte) ([]byte, error) {
	if len(c.publicKeys) == 0 {
		return nil, errors.New("gpg: missing public keys")
	}
	return gpgx.Encrypt(data, c.publicKeys)
}

func (c *GPGCryptor) decrypt(data []byte) ([]byte, error) {
	if len(c.privateKeys) == 0 {
		return nil, errors.New("gpg: missing private keys")
	}
	return gpgx.Decrypt(data, c.privateKeys)
}

var _ Cryptor = (&GPGCryptor{})
