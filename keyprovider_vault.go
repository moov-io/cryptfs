package cryptfs

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/moov-io/cryptfs/stream"

	"github.com/hashicorp/vault/api"
)

type vaultKeyProvider struct {
	client *api.Client
	config VaultConfig
}

func NewVaultKeyProvider(conf VaultConfig) (stream.KeyProvider, error) {
	vaultConf := api.DefaultConfig()
	vaultConf.Address = conf.Address
	vaultConf.HttpClient = &http.Client{
		Timeout: 30 * time.Second,
	}

	client, err := api.NewClient(vaultConf)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	// authenticate to verify the Vault client is healthy
	if err := conf.authenticate(client); err != nil {
		return nil, fmt.Errorf("unable to authenticate - %w", err)
	}

	return &vaultKeyProvider{
		client: client,
		config: conf,
	}, nil
}

func (p *vaultKeyProvider) auth() error {
	return p.config.authenticate(p.client)
}

func (p *vaultKeyProvider) Healthy() error {
	if err := p.auth(); err != nil {
		return err
	}

	_, err := p.client.Sys().Health()
	if err != nil {
		return fmt.Errorf("checking Vault health: %v", err)
	}

	return nil
}

func (p *vaultKeyProvider) GenerateKey() (*stream.DataKey, error) {
	if err := p.config.authenticate(p.client); err != nil {
		return nil, err
	}

	res, err := p.client.Logical().Write(
		fmt.Sprintf("/transit/datakey/plaintext/%s", p.config.KeyName),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("generating data key: %w", err)
	}

	// Vault returns base64-encoded plaintext key
	b64Key, ok := res.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("casting plaintext key to string from %T", res.Data["plaintext"])
	}

	plaintext, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("decoding plaintext key: %w", err)
	}

	ciphertext, ok := res.Data["ciphertext"].(string)
	if !ok {
		return nil, fmt.Errorf("casting ciphertext key to string from %T", res.Data["ciphertext"])
	}

	return &stream.DataKey{
		Plaintext:  plaintext,
		WrappedKey: []byte(ciphertext),
	}, nil
}

func (p *vaultKeyProvider) UnwrapKey(wrappedKey []byte) ([]byte, error) {
	if err := p.config.authenticate(p.client); err != nil {
		return nil, err
	}

	params := map[string]interface{}{
		"ciphertext": string(wrappedKey),
	}
	res, err := p.client.Logical().Write(
		fmt.Sprintf("/transit/decrypt/%s", p.config.KeyName),
		params,
	)
	if err != nil {
		return nil, fmt.Errorf("unwrapping data key: %w", err)
	}

	b64Key, ok := res.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("casting unwrapped key to string from %T", res.Data["plaintext"])
	}

	plaintext, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("decoding unwrapped key: %w", err)
	}

	return plaintext, nil
}
