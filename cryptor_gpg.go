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
	"errors"
	"fmt"
	"io"

	"github.com/moov-io/cryptfs/internal/gpgx"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
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

	var signedData []byte
	var err error

	if len(c.privateKeys) > 0 {
		signedData, err = gpgx.Sign(data, c.privateKeys)
		if err != nil {
			return nil, fmt.Errorf("gpg: failed to sign data: %w", err)
		}
	} else {
		signedData = data
	}

	encryptedData, err := gpgx.Encrypt(signedData, c.publicKeys)
	if err != nil {
		return nil, fmt.Errorf("gpg: failed to encrypt data: %w", err)
	}

	return encryptedData, nil
}

func (c *GPGCryptor) decrypt(data []byte) ([]byte, error) {
	if len(c.privateKeys) == 0 {
		return nil, errors.New("gpg: missing private keys")
	}

	decryptedData, err := gpgx.Decrypt(data, c.privateKeys)
	if err != nil {
		return nil, fmt.Errorf("gpg: failed to decrypt data: %w", err)
	}

	if len(c.publicKeys) > 0 {
		armorBlock, err := armor.Decode(bytes.NewReader(decryptedData))
		if err != nil {
			return nil, fmt.Errorf("gpg: failed to decode armored message: %w", err)
		}

		// Read the message details and check if it contains a signature
		signer, err := openpgp.ReadMessage(armorBlock.Body, c.publicKeys, nil, &packet.Config{})
		if err != nil {
			return nil, fmt.Errorf("gpg: failed to read PGP message: %w", err)
		}

		if signer.SignedBy != nil {
			var expectedFingerprint [20]byte
			copy(expectedFingerprint[:], c.publicKeys[0].PrimaryKey.Fingerprint[:])

			// Verify the signature and extract the original cleartext message
			cleartext, err := io.ReadAll(signer.UnverifiedBody)
			if err != nil {
				return nil, fmt.Errorf("gpg: failed to read signed message body: %w", err)
			}

			if !bytes.Equal(signer.SignedBy.PublicKey.Fingerprint[:], expectedFingerprint[:]) {
				return nil, errors.New("gpg: signature verification failed: public key fingerprint does not match the expected fingerprint")
			}

			if signer.SignatureError != nil {
				return nil, fmt.Errorf("gpg: signature verification error: %w", signer.SignatureError)
			}

			return cleartext, nil
		} else {
			// No signature found, return the decrypted data as is
			return decryptedData, nil
		}
	}

	return decryptedData, nil
}

var _ Cryptor = (&GPGCryptor{})
