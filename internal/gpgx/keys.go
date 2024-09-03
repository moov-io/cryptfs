// Copyright 2020 The Moov Authors
// Use of this source code is governed by an Apache License
// license that can be found in the LICENSE file.

package gpgx

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// ReadArmoredKey attempts to read the filepath and parses an armored GPG key
func ReadArmoredKey(data io.Reader) (openpgp.EntityList, error) {
	return openpgp.ReadArmoredKeyRing(data)
}

// ReadArmoredKeyFile attempts to read the filepath and parses an armored GPG key
func ReadArmoredKeyFile(path string) (openpgp.EntityList, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if fd != nil {
		defer fd.Close()
	}
	return ReadArmoredKey(fd)
}

// ReadPrivateKey attempts to read the filepath and parses an armored GPG private key
func ReadPrivateKey(data io.Reader, password []byte) (openpgp.EntityList, error) {
	entityList, err := ReadArmoredKey(data)
	if err != nil {
		return nil, err
	}
	return decryptPrivateKey(entityList, password)
}

// ReadPrivateKeyFile attempts to read the filepath and parses an armored GPG private key
func ReadPrivateKeyFile(path string, password []byte) (openpgp.EntityList, error) {
	entityList, err := ReadArmoredKeyFile(path)
	if err != nil {
		return nil, err
	}
	return decryptPrivateKey(entityList, password)
}

func decryptPrivateKey(entityList openpgp.EntityList, password []byte) (openpgp.EntityList, error) {
	if len(entityList) == 0 {
		return nil, errors.New("gpg: no entities found")
	}

	entity := entityList[0]

	// Get the passphrase and read the private key.
	if entity.PrivateKey != nil && len(password) > 0 {
		err := entity.PrivateKey.Decrypt(password)
		if err != nil {
			return nil, fmt.Errorf("decrypting private key failed: %w", err)
		}
	}
	for idx, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && len(password) > 0 {
			err := subkey.PrivateKey.Decrypt(password)
			if err != nil {
				return nil, fmt.Errorf("decrypting subkey %d failed: %w", idx, err)
			}
		}
	}

	return entityList, nil
}

func Encrypt(msg []byte, pubkeys openpgp.EntityList) ([]byte, error) {
	var encCloser, armorCloser io.WriteCloser
	var err error

	cfg := &packet.Config{
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.NoCompression,
	}

	encbuf := new(bytes.Buffer)
	encCloser, err = openpgp.Encrypt(encbuf, pubkeys, nil, nil, cfg)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	_, err = encCloser.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("encCloser.Write: %w", err)
	}

	err = encCloser.Close()
	if err != nil {
		return nil, fmt.Errorf("encCloser.Close: %w", err)
	}

	armorbuf := new(bytes.Buffer)
	armorCloser, err = armor.Encode(armorbuf, "PGP MESSAGE", nil)
	if err != nil {
		return nil, fmt.Errorf("armor encode: %w", err)
	}

	_, err = armorCloser.Write(encbuf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("armorCloser.Write : %w", err)
	}

	err = armorCloser.Close()
	if err != nil {
		return nil, fmt.Errorf("armorCloser.Close : %w", err)
	}

	return armorbuf.Bytes(), nil
}

func Decrypt(cipherArmored []byte, keys openpgp.EntityList) ([]byte, error) {
	if !(len(keys) == 1 && keys[0].PrivateKey != nil) {
		return nil, errors.New("requires a single private key")
	}
	return readMessage(cipherArmored, keys)
}

func readMessage(armoredMessage []byte, keys openpgp.EntityList) ([]byte, error) {
	decbuf := bytes.NewBuffer(armoredMessage)
	result, err := armor.Decode(decbuf)
	if err != nil {
		return nil, fmt.Errorf("error decoding armored message: %w", err)
	}

	md, err := openpgp.ReadMessage(result.Body, keys, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("error reading PGP message: %w", err)
	}

	if len(keys) == 2 {
		if md.SignedBy == nil || md.SignedBy.PublicKey == nil {
			return nil, errors.New("verifying public key included, but message is not signed")
		}
		if !bytes.Equal(md.SignedBy.PublicKey.Fingerprint, keys[1].PrimaryKey.Fingerprint) {
			return nil, errors.New("signature pubkey doesn't match signing pubkey")
		}
	}

	bytes, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("error reading decrypted message body: %w", err)
	}

	if md.SignatureError != nil {
		return nil, fmt.Errorf("signature verification error: %w", md.SignatureError)
	}

	return bytes, nil
}
