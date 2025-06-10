## Future Releases

Please refer to the [Github Releases](https://github.com/moov-io/cryptfs/releases) page for moov-go for future updates.

## v0.8.0 (Released 2024-09-03)

IMPROVEMENTS

- config: verify json/yaml files read as expected
- feat: support HMAC key to verify data
- feat: verify GPG signatures, sign messages
- fix: avoid panic in gzip decompress with nil input
- gpgx: check errors when decrypting private keys
- gpgx: improve error messages
- refactor: wrap errors for clarity
- test: verify HMAC with gpg
- test: verify Sign / VerifySignature

BUILD

- chore(deps): update actions/checkout action to v4
- chore(deps): update actions/setup-go action to v5
- chore(deps): update dependency go to v1.22.6
- chore(deps): update github/codeql-action action to v3

## v0.7.3 (Released 2024-07-11)

BUILD

- chore(deps): update dependency go to v1.22.4
- chore(deps): update dependency go to v1.22.5
- chore(deps): update hashicorp/vault docker tag to v1.17
- fix(deps): update module github.com/hashicorp/vault/api to v1.14.0
- gpgx: update example keys

## v0.7.2 (Released 2024-05-10)

IMPROVEMENTS

- fix: set vault cryptor in FromConfig

BUILD

- build: run tests on oldstable, run "go test" on windows
- chore(deps): update dependency go to v1.22.3
- chore(deps): update hashicorp/vault docker tag to v1.16
- fix(deps): update module github.com/hashicorp/vault/api to v1.13.0
- fix(deps): update module github.com/protonmail/go-crypto to v1

## v0.7.1 (Released 2023-12-19)

BUILD

- build: always use latest Go release
- build: update moov-io/base and golang.org/x/crypto
- chore(deps): update hashicorp/vault docker tag to v1.15

## v0.7.0 (Released 2023-07-14)

IMPROVEMENTS

- feat: add Vault cryptor

## v0.6.0 (Released 2023-07-12)

IMPROVEMENTS

- feat: add config struct for creating *FS instances
- feat: add nothing cryptor

BUILD

- fix(deps): update github.com/protonmail/go-crypto digest to e01326f

## v0.5.0 (Released 2023-06-29)

IMPROVEMENTS

- docs: godoc headers for Open and Disfigure
- feat: add (gzip) compression

BUILD

- chore: update github.com/ProtonMail/go-crypto to a94812496cf5
- fix(deps): update module github.com/stretchr/testify to v1.8.4

## v0.4.2 (Released 2023-05-19)

BUILD

- fix(deps): update module github.com/stretchr/testify to v1.8.3
- fix(deps): update github.com/ProtonMail/go-crypto digest to a9481249

## v0.4.1 (Released 2023-02-27)

IMPROVEMENTS

- cmd/cryptfs: cleanup main code and add tests

BUILD

- build: remove deprecated ioutil functions
- fix(deps): update github.com/protonmail/go-crypto digest to 7d5c6f0
- fix(deps): update module github.com/stretchr/testify to v1.8.2
- build: update golang.org/x/sys to v0.5.0

## v0.4.0 (Released 2022-06-07)

ADDITIONS

- Add GPG Cryptor that can encrypt and decrypt messages

BUILD

- fix(deps): update module github.com/stretchr/testify to v1.7.2

## v0.3.0 (Released 2022-06-02)

We've noticed that new users to this library can use the `Coder` and `Cryptor` methods these incorrectly.
Since these can be confusing for new users we're removing them from the public API.

BREAKING CHANGES

- fix: unexport `Coder` and `Cryptor` methods

IMPROVEMENTS

- docs: fix cli decrypt example

BUILD

- fix(deps): update module github.com/stretchr/testify to v1.7.1

## v0.2.0 (Released 2022-03-09)

ADDITIONS

- cmd/cryptfs: setup a CLI tool for basic operations

## v0.1.0 (Released 2021-12-10)

Initial release
