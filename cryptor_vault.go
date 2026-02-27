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
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/vault/api"
)

type VaultConfig struct {
	Address string `json:"address" yaml:"address"`

	Token      *TokenConfig      `json:"token" yaml:"token"`
	Kubernetes *KubernetesConfig `json:"kubernetes" yaml:"kubernetes"`

	// KeyName is the named transit key to use
	KeyName string `json:"keyName" yaml:"keyName"`
}

type TokenConfig struct {
	Token string `json:"token" yaml:"token"`
}

type KubernetesConfig struct {
	Path string `json:"path" yaml:"path"`
}

type vaultClient struct {
	client *api.Client
	config VaultConfig
}

func newVaultClient(conf VaultConfig) (*vaultClient, error) {
	vaultConf := api.DefaultConfig()
	vaultConf.Address = conf.Address
	vaultConf.HttpClient = &http.Client{
		Timeout: 30 * time.Second,
	}

	client, err := api.NewClient(vaultConf)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	vc := &vaultClient{
		client: client,
		config: conf,
	}
	if err := vc.auth(); err != nil {
		return nil, fmt.Errorf("unable to authenticate - %w", err)
	}
	if err := vc.Healthy(); err != nil {
		return nil, fmt.Errorf("vault isn't healthy - %w", err)
	}

	return vc, nil
}

func (vc *vaultClient) auth() error {
	if vc.config.Kubernetes != nil {
		bs, err := os.ReadFile(vc.config.Kubernetes.Path)
		if err != nil {
			return fmt.Errorf("problem reading kubernetes path: %w", err)
		}
		vc.client.SetToken(string(bs))
		return nil
	}
	if vc.config.Token != nil {
		vc.client.SetToken(vc.config.Token.Token)
		return nil
	}
	return errors.New("must specified a auth configuration")
}

func (vc *vaultClient) Healthy() error {
	if err := vc.auth(); err != nil {
		return err
	}

	_, err := vc.client.Sys().Health()
	if err != nil {
		return fmt.Errorf("checking Vault health: %v", err)
	}

	return nil
}

func NewVaultCryptor(conf VaultConfig) (*VaultCryptor, error) {
	vc, err := newVaultClient(conf)
	if err != nil {
		return nil, err
	}

	return &VaultCryptor{vaultClient: vc}, nil
}

type VaultCryptor struct {
	*vaultClient
}

func (v *VaultCryptor) encrypt(plaintext []byte) ([]byte, error) {
	if err := v.auth(); err != nil {
		return nil, err
	}

	params := map[string]interface{}{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}
	res, err := v.client.Logical().Write(fmt.Sprintf("/transit/encrypt/%s", v.config.KeyName), params)
	if err != nil {
		return nil, fmt.Errorf("encrypting data: %v", err)
	}

	data := res.Data["ciphertext"]
	ciphertext, ok := data.(string)
	if !ok {
		return nil, fmt.Errorf("casting ciphertext to string from %T", data)
	}
	return []byte(ciphertext), nil
}

func (v *VaultCryptor) decrypt(ciphertext []byte) ([]byte, error) {
	if err := v.auth(); err != nil {
		return nil, err
	}

	params := map[string]interface{}{"ciphertext": string(ciphertext)}
	res, err := v.client.Logical().Write(fmt.Sprintf("/transit/decrypt/%s", v.config.KeyName), params)
	if err != nil {
		return nil, fmt.Errorf("decrypting data: %v", err)
	}

	data := res.Data["plaintext"]
	base64Plaintext, ok := data.(string)
	if !ok {
		return nil, fmt.Errorf("casting decrypted plaintext to string from %T", data)
	}

	plaintext, err := base64.StdEncoding.DecodeString(base64Plaintext)
	if err != nil {
		return nil, fmt.Errorf("decoding plaintext: %v", err)
	}
	return plaintext, nil
}
