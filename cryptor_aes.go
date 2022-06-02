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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

type AESCryptor struct {
	cphr cipher.Block
}

// NewAESCryptor returns an Cryptor which performs AES encryption/decryption.
//
// The key must be 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func NewAESCryptor(key []byte) (*AESCryptor, error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &AESCryptor{cphr: cphr}, nil
}

func (c *AESCryptor) encrypt(data []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(c.cphr)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := gcm.Seal(nonce, nonce, data, nil)
	return out, nil
}

func (c *AESCryptor) decrypt(ciphertext []byte) ([]byte, error) {
	gcm, err := cipher.NewGCM(c.cphr)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("nonce is too small")
	}
	nonce, encryptedMessage := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedMessage, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
