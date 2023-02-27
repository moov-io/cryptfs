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
