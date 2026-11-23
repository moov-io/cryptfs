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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func fakeVaultServer(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVaultConfig_AddressFromEnv(t *testing.T) {
	srv := fakeVaultServer(t)

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "")

	cc, err := NewVaultCryptor(VaultConfig{
		Token:   &TokenConfig{Token: "myroot"},
		KeyName: "testkey",
	})
	require.NoError(t, err)
	require.Equal(t, srv.URL, cc.client.Address())
}

func TestVaultConfig_TokenFromEnv(t *testing.T) {
	srv := fakeVaultServer(t)

	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "envtoken")

	cc, err := NewVaultCryptor(VaultConfig{
		Address: srv.URL,
		KeyName: "testkey",
	})
	require.NoError(t, err)
	require.Equal(t, "envtoken", cc.client.Token())
}

func TestVaultConfig_MissingAuth(t *testing.T) {
	srv := fakeVaultServer(t)

	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")

	_, err := NewVaultCryptor(VaultConfig{
		Address: srv.URL,
		KeyName: "testkey",
	})
	require.ErrorContains(t, err, "must specify an auth configuration")
}
