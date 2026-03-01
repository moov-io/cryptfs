package stream

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStaticKeyProvider(t *testing.T) {
	key := []byte("1234567890123456") // AES-128

	kp := NewStaticKeyProvider(key)

	t.Run("GenerateKey", func(t *testing.T) {
		dk, err := kp.GenerateKey()
		require.NoError(t, err)
		require.Equal(t, key, dk.Plaintext)
		require.Nil(t, dk.WrappedKey)
	})

	t.Run("UnwrapKey ignores input", func(t *testing.T) {
		_, err := kp.UnwrapKey([]byte("anything"))
		require.Error(t, err)
	})

	t.Run("key is copied", func(t *testing.T) {
		original := []byte("abcdefghijklmnop")
		kp := NewStaticKeyProvider(original)

		// Mutate the original — provider should be unaffected
		original[0] = 'X'

		dk, err := kp.GenerateKey()
		require.NoError(t, err)
		require.Equal(t, byte('a'), dk.Plaintext[0])
	})
}
