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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestFromConfig(t *testing.T) {
	var conf Config

	t.Run("zero value", func(t *testing.T) {
		fsys, err := FromConfig(conf)
		require.NoError(t, err)
		require.Equal(t, "*cryptfs.nothingCryptor", fmt.Sprintf("%T", fsys.cryptor))

		testCryptFS(t, fsys)
	})

	t.Run("gzip + base64", func(t *testing.T) {
		conf.Compression.Gzip = &GzipConfig{}
		conf.Encoding.Base64 = true

		fsys, err := FromConfig(conf)
		require.NoError(t, err)
		require.Equal(t, "*cryptfs.nothingCryptor", fmt.Sprintf("%T", fsys.cryptor))

		testCryptFS(t, fsys)
	})

	t.Run("AES", func(t *testing.T) {
		conf.Encryption.AES = &AESConfig{
			Key: strings.Repeat("1", 16),
		}

		fsys, err := FromConfig(conf)
		require.NoError(t, err)
		require.Equal(t, "*cryptfs.AESCryptor", fmt.Sprintf("%T", fsys.cryptor))

		testCryptFS(t, fsys)
	})

	t.Run("AES - filepath error", func(t *testing.T) {
		conf.Encryption.AES.Key = ""
		conf.Encryption.AES.KeyPath = "/does/not/exist"

		fsys, err := FromConfig(conf)
		require.Error(t, err)
		require.Nil(t, fsys)
	})

	t.Run("GPG one-sided", func(t *testing.T) {
		conf.Encryption.AES = nil
		conf.Encryption.GPG = &GPGConfig{
			PublicPath: filepath.Join("internal", "gpgx", "testdata", "key.pub"),
		}

		fsys, err := FromConfig(conf)
		require.NoError(t, err)

		parent := t.TempDir()
		path := filepath.Join(parent, "foo.txt")
		err = fsys.WriteFile(path, []byte("hello, world"), 0600)
		require.NoError(t, err)

		// Setup fsys with private keys (for decryption)
		conf.Encryption.GPG.PublicPath = ""
		conf.Encryption.GPG.PrivatePath = filepath.Join("internal", "gpgx", "testdata", "key.priv")
		conf.Encryption.GPG.PrivatePassword = "password"

		fsys, err = FromConfig(conf)
		require.NoError(t, err)
		require.Equal(t, "*cryptfs.GPGCryptor", fmt.Sprintf("%T", fsys.cryptor))

		bs, err := fsys.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, "hello, world", string(bs))
	})

	t.Run("GPG both filepaths", func(t *testing.T) {
		conf.Encryption.AES = nil
		conf.Encryption.GPG = &GPGConfig{
			PublicPath:      filepath.Join("internal", "gpgx", "testdata", "key.pub"),
			PrivatePath:     filepath.Join("internal", "gpgx", "testdata", "key.priv"),
			PrivatePassword: "password",
		}

		fsys, err := FromConfig(conf)
		require.NoError(t, err)
		require.Equal(t, "*cryptfs.GPGCryptor", fmt.Sprintf("%T", fsys.cryptor))

		testCryptFS(t, fsys)
	})

	t.Run("Vault", func(t *testing.T) {
		shouldSkipDockerTest(t)

		conf.Encryption.GPG = nil
		conf.Encryption.Vault = &VaultConfig{
			Address: "http://localhost:8200",
			Token: &TokenConfig{
				Token: "myroot",
			},
			KeyName: "testkey",
		}

		fsys, err := FromConfig(conf)
		require.NoError(t, err)
		require.Equal(t, "*cryptfs.VaultCryptor", fmt.Sprintf("%T", fsys.cryptor))

		testCryptFS(t, fsys)
	})
}

// FromFile will read the given path and unmarshal a Config in YAML or JSON format.
// If a reading a config doesn't fail an *FS will be returned from the config.
func FromFile(path string) (*FS, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s failed: %w", path, err)
	}

	var conf Config
	yamlDecoder := yaml.NewDecoder(bytes.NewReader(bs))
	yamlDecoder.KnownFields(true)
	yamlError := yamlDecoder.Decode(&conf)
	if yamlError == nil {
		return FromConfig(conf)
	}

	jsonDecoder := json.NewDecoder(bytes.NewReader(bs))
	jsonDecoder.DisallowUnknownFields()

	jsonError := jsonDecoder.Decode(&conf)
	if jsonError == nil {
		return FromConfig(conf)
	}

	return nil, fmt.Errorf("error reading config from %s\n  %w\n  %w", path, yamlError, jsonError)
}

func TestFromFile(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		fsys, err := FromFile(filepath.Join("testdata", "valid.yaml"))
		require.NoError(t, err)
		require.NotNil(t, fsys)
		require.Equal(t, "*cryptfs.AESCryptor", fmt.Sprintf("%T", fsys.cryptor))
		require.Equal(t, "de57e09f-e299-4de6-94ab-cd89d894c900", string(fsys.hmacKey))

		fsys, err = FromFile(filepath.Join("testdata", "valid.json"))
		require.NoError(t, err)
		require.NotNil(t, fsys)
		require.Equal(t, "*cryptfs.GPGCryptor", fmt.Sprintf("%T", fsys.cryptor))
		require.Equal(t, "de57e09f-e299-4de6-94ab-cd89d894c900", string(fsys.hmacKey))
	})
}
