package gpgx

import (
	"bytes"
	"crypto"
	"errors"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Sign signs the provided data using the private key(s) in the entity list.
// It returns the signed, armored data.
func Sign(data []byte, privateKeys openpgp.EntityList) ([]byte, error) {
	if len(privateKeys) == 0 {
		return nil, errors.New("no private keys provided for signing")
	}

	var signedData bytes.Buffer
	signWriter, err := openpgp.Sign(&signedData, privateKeys[0], nil, &packet.Config{
		DefaultHash: crypto.SHA256,
	})
	if err != nil {
		return nil, err
	}

	_, err = signWriter.Write(data)
	if err != nil {
		return nil, err
	}

	err = signWriter.Close()
	if err != nil {
		return nil, err
	}

	var armoredData bytes.Buffer
	armorWriter, err := armor.Encode(&armoredData, "PGP SIGNATURE", nil)
	if err != nil {
		return nil, err
	}

	_, err = armorWriter.Write(signedData.Bytes())
	if err != nil {
		return nil, err
	}

	err = armorWriter.Close()
	if err != nil {
		return nil, err
	}

	return armoredData.Bytes(), nil
}

// VerifySignature verifies the signature on the provided data using the public key(s).
// It returns the original cleartext data if the verification is successful, or an error if it fails.
func VerifySignature(signedData []byte, publicKeys openpgp.EntityList, expectedFingerprint [20]byte) ([]byte, error) {
	armorBlock, err := armor.Decode(bytes.NewReader(signedData))
	if err != nil {
		return nil, err
	}

	if armorBlock.Type != "PGP SIGNATURE" {
		return nil, errors.New("invalid PGP signature block")
	}

	signer, err := openpgp.ReadMessage(armorBlock.Body, publicKeys, nil, &packet.Config{})
	if err != nil {
		return nil, err
	}

	if signer.SignedBy == nil || signer.SignatureError != nil {
		return nil, errors.New("signature verification failed")
	}

	if !bytes.Equal(signer.SignedBy.PublicKey.Fingerprint[:], expectedFingerprint[:]) {
		return nil, errors.New("signature verification failed: public key fingerprint does not match the expected fingerprint")
	}

	cleartext, err := io.ReadAll(signer.UnverifiedBody)
	if err != nil {
		return nil, err
	}

	return cleartext, nil
}
