package cryptfs

import (
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
)

func TestVaultKeyProvider(t *testing.T) {
	shouldSkipDockerTest(t)

	conf := VaultConfig{
		Address: "http://localhost:8200",
		Token:   &TokenConfig{Token: "myroot"},
		KeyName: "testkey",
	}

	vaultConf := api.DefaultConfig()
	vaultConf.Address = conf.Address
	client, err := api.NewClient(vaultConf)
	require.NoError(t, err)
	client.SetToken("myroot")

	kp := NewVaultKeyProvider(client, conf)

	t.Run("generate and unwrap", func(t *testing.T) {
		dk, err := kp.GenerateKey()
		require.NoError(t, err)
		require.Len(t, dk.Plaintext, 32, "Vault default data key is 256-bit")
		require.NotEmpty(t, dk.WrappedKey, "wrapped key should be non-empty")

		recovered, err := kp.UnwrapKey(dk.WrappedKey)
		require.NoError(t, err)
		require.Equal(t, dk.Plaintext, recovered, "unwrapped key must match original")
	})

	t.Run("multiple keys are unique", func(t *testing.T) {
		dk1, err := kp.GenerateKey()
		require.NoError(t, err)

		dk2, err := kp.GenerateKey()
		require.NoError(t, err)

		require.NotEqual(t, dk1.Plaintext, dk2.Plaintext, "each data key should be unique")
	})
}
