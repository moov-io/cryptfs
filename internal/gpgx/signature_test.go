package gpgx

import (
	"testing"

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
