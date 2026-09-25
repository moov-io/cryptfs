package gpgx

import (
	"bytes"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/stretchr/testify/require"
)

func TestGPG_Signature(t *testing.T) {
	privateKey, err := ReadPrivateKeyFile(privateKeyPath, password)
	require.NoError(t, err)

	input := []byte("hello, world")
	signedData, err := Sign(input, privateKey)
	require.NoError(t, err)
	require.NotEmpty(t, signedData)

	publicKey, err := ReadArmoredKeyFile(publicKeyPath)
	require.NoError(t, err)
	require.Len(t, publicKey, 1)

	var expectedFingerprint [20]byte
	copy(expectedFingerprint[:], publicKey[0].PrimaryKey.Fingerprint[:])

	verifiedBytes, err := VerifySignature(signedData, publicKey, expectedFingerprint)
	require.NoError(t, err)
	require.Equal(t, string(input), string(verifiedBytes))
}

func TestVerifySignatureRejectsTamperedBody(t *testing.T) {
	privateKey, err := ReadPrivateKeyFile(privateKeyPath, password)
	require.NoError(t, err)

	signedData, err := Sign([]byte("hello, world"), privateKey)
	require.NoError(t, err)

	block, err := armor.Decode(bytes.NewReader(signedData))
	require.NoError(t, err)
	raw, err := io.ReadAll(block.Body)
	require.NoError(t, err)

	idx := bytes.Index(raw, []byte("hello, world"))
	require.NotEqual(t, -1, idx)
	raw[idx+len("hello, world")-1] = 'X'

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, "PGP SIGNATURE", nil)
	require.NoError(t, err)
	_, err = w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	publicKey, err := ReadArmoredKeyFile(publicKeyPath)
	require.NoError(t, err)
	var expectedFingerprint [20]byte
	copy(expectedFingerprint[:], publicKey[0].PrimaryKey.Fingerprint[:])

	_, err = VerifySignature(buf.Bytes(), publicKey, expectedFingerprint)
	require.Error(t, err)
}
