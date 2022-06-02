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
