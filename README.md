[![Moov Banner Logo](https://user-images.githubusercontent.com/20115216/104214617-885b3c80-53ec-11eb-8ce0-9fc745fb5bfc.png)](https://github.com/moov-io)

<p align="center">
  <a href="https://pkg.go.dev/github.com/moov-io/cryptfs">Go Documentation</a>
  ·
  <a href="https://pkg.go.dev/github.com/moov-io/cryptfs/stream">Streaming API Documentation</a>
  ·
  <a href="https://slack.moov.io/">Community</a>
  ·
  <a href="https://moov.io/blog/">Blog</a>
  <br>
  <br>
</p>

[![GoDoc](https://godoc.org/github.com/moov-io/cryptfs?status.svg)](https://godoc.org/github.com/moov-io/cryptfs)
[![Build Status](https://github.com/moov-io/cryptfs/workflows/Go/badge.svg)](https://github.com/moov-io/cryptfs/actions)
[![Coverage Status](https://codecov.io/gh/moov-io/cryptfs/branch/master/graph/badge.svg)](https://codecov.io/gh/moov-io/cryptfs)
[![Go Report Card](https://goreportcard.com/badge/github.com/moov-io/cryptfs)](https://goreportcard.com/report/github.com/moov-io/cryptfs)
[![Repo Size](https://img.shields.io/github/languages/code-size/moov-io/cryptfs?label=project%20size)](https://github.com/moov-io/cryptfs)
[![Apache 2 License](https://img.shields.io/badge/license-Apache2-blue.svg)](https://raw.githubusercontent.com/moov-io/cryptfs/master/LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/moov-io/cryptfs)](https://github.com/moov-io/cryptfs)
[![Twitter](https://img.shields.io/twitter/follow/moov?style=social)](https://twitter.com/moov?lang=en)

# moov-io/cryptfs
Moov's mission is to give developers an easy way to create and integrate bank processing into their own software products. Our open source projects are each focused on solving a single responsibility in financial services and designed around performance, scalability, and ease of use.

cryptfs implements Go's [`io/fs.FS`](https://pkg.go.dev/io/fs#FS) and [`io/fs.ReadFileFS`](https://pkg.go.dev/io/fs#ReadFileFS) interfaces for the local filesystem. `WriteFile` encrypts data before it is written and `ReadFile` decrypts data after it is read. This is useful as a library because it offers applications a well tested routine for keeping data protected.

> [!IMPORTANT]
> `Open` returns the file as stored on disk (ciphertext). Only `ReadFile` (and `fs.ReadFile`, which calls it) and `Reveal` decrypt. Generic `fs.FS` consumers that call `Open`, such as `http.FS`, `fs.WalkDir` with `Open`, or `template.ParseFS`, receive ciphertext.

## Project Status

cryptfs is included in multiple open-source projects Moov offers and is used in production environments. Please star the project if you are interested in its progress. If you find any bugs or desire additional encryption/encoding algorithms we would appreciate an issue or pull request. Thanks!

## Usage

Cryptfs is usable as a Go library in your applications. This needs to be initialized prior to reading or writing any files.

```
go get github.com/moov-io/cryptfs@latest
```

Cryptfs supports:

- Encryption: AES-GCM (`NewAESCryptor`), GPG (`NewGPGCryptor*`, `NewGPGEncryptor*`, `NewGPGDecryptor*`) and Vault Transit (`NewVaultCryptor`)
- Encoding: Base64 Standard Raw (`Base64()`)
- Compression: gzip (`Gzip()`, `GzipLevel(level)`, `GzipRequired(level)`)
- Integrity: HMAC-SHA256 (`SetHMACKey`)
- Configuration from JSON or YAML (`FromConfig`)
- Streaming encryption for large files (the [`stream`](https://pkg.go.dev/github.com/moov-io/cryptfs/stream) sub-package)

### Choosing an API

The in-memory API and the streaming API write **different formats**. The formats are not interchangeable. `ReadFile` / `Reveal` cannot read a file written by `stream.NewWriter`, and `stream.NewReader` cannot read a file written by `WriteFile` / `Disfigure`. For example, `ReadFile` on a streamed file fails with `decoding: base64 decode: illegal base64 data at input byte 4`. The [command line tool](./cmd/cryptfs) uses the in-memory format.

- Use the in-memory API for small files, for GPG, and for Vault encryption of each file.
- Use the streaming API for large files, for cloud buckets (`gocloud.dev/blob`), and for Vault envelope encryption.

To move existing files from one format to the other, read each file with the API that wrote it and write it again with the other API. For example, call `fsys.ReadFile(path)` and then copy the plaintext into a `stream.NewWriter`.

### In-memory API (`Disfigure` / `Reveal`)

The original `[]byte`-based API encrypts and decrypts data entirely in memory.

<details>
<summary>AES Cryptor</summary>

```go
key := []byte("1234567812345678") // insecure key

fsys, err := cryptfs.FromCryptor(cryptfs.NewAESCryptor(key))
if err != nil {
    return err
}

fsys.SetCoder(cryptfs.Base64()) // optional, default is the raw bytes
```

The key length selects the AES variant: 16 bytes for AES-128, 24 bytes for AES-192 and 32 bytes for AES-256. Other lengths fail with `crypto/aes: invalid key size`. For production, generate a random 32-byte key and keep it in a secret manager, not in source code. For example:

```
openssl rand -base64 32
```

Decode the base64 value to get the 32 raw bytes before you call `NewAESCryptor`.

</details>

<details>
<summary>GPG Cryptor</summary>

```go
publicKeyPath := "public.asc"
privateKeyPath := "private.asc"
password := []byte("private key password") // must be a []byte

fsys, err := cryptfs.FromCryptor(cryptfs.NewGPGCryptorFile(publicKeyPath, privateKeyPath, password))
if err != nil {
    return err
}

fsys.SetCoder(cryptfs.Base64()) // optional, default is the raw bytes
```

The key files must be ASCII-armored. You can export them with `gpg`:

```
gpg --armor --export user@example.com > public.asc
gpg --armor --export-secret-keys user@example.com > private.asc
```

Other constructors:

- `NewGPGEncryptorFile(publicKeyPath)` / `NewGPGEncryptor(io.Reader)`: encrypt only. Written files are not signed.
- `NewGPGDecryptorFile(privateKeyPath, password)` / `NewGPGDecryptor(io.Reader, password)`: decrypt only. Signatures are not checked.
- `NewGPGCryptorFile(publicKeyPath, privateKeyPath, password)` / `NewGPGCryptor(publicKey, privateKey io.Reader, password)`: encrypt and decrypt.

**Wire format and compatibility with the `gpg` CLI**

When a private key is set, `GPGCryptor` signs the data, ASCII-armors the signed message (`-----BEGIN PGP SIGNATURE-----`), encrypts that armored message, and ASCII-armors the result (`-----BEGIN PGP MESSAGE-----`). This format has these limits:

- `gpg -d` on a file written with a private key gives the inner armored signed message, not the plaintext. Run `gpg -d` a second time on that output to get the plaintext.
- Decryption accepts only ASCII-armored input. Binary files from `gpg -e` (without `-a`) fail with `error decoding armored message: EOF`.
- `NewGPGCryptorFile` expects the nested signed format. Files from `gpg -a -e` or `gpg -a -e -s` fail with `failed to decode armored message: EOF`.
- For armored files from partners that use the `gpg` CLI, use `NewGPGDecryptorFile`.

</details>

<details>
<summary>Vault Cryptor</summary>

`NewVaultCryptor` sends the data of each file to Vault Transit for encryption and decryption. Use the streaming API with `NewVaultKeyProvider` for large files. See [Vault envelope encryption](#streaming-api-streamnewwriter--streamnewreader) for the transit setup and the required policy.

```go
fsys, err := cryptfs.FromCryptor(cryptfs.NewVaultCryptor(cryptfs.VaultConfig{
    Address: "http://127.0.0.1:8200",
    Token:   &cryptfs.TokenConfig{Token: os.Getenv("VAULT_TOKEN")},
    KeyName: "testkey",
}))
if err != nil {
    return err
}
```

</details>

<details>
<summary>Compression and HMAC</summary>

```go
fsys.SetCompression(cryptfs.Gzip())            // or GzipLevel(level), or GzipRequired(level)
fsys.SetHMACKey([]byte("hmac secret key"))     // optional
```

Compression occurs before encryption. `GzipRequired` fails to read data that is not gzip compressed. The other gzip options also read data that is not compressed.

When an HMAC key is set, cryptfs calculates an HMAC-SHA256 of the encrypted data and writes it in front of the encrypted data. `ReadFile` and `Reveal` check the HMAC before decryption and fail with `invalid MAC, data integrity could be compromised` if the data changed. Use the same compression and HMAC settings to read and write a file.

</details>

<details>
<summary>Configuration (JSON or YAML)</summary>

`FromConfig` creates an `*FS` from a `cryptfs.Config`. Set only one of `aes`, `gpg` or `vault`.

```yaml
compression:
  gzip:
    level: -1
    required: true
encryption:
  aes:
    key: "1234567887654321" # or keyPath: "/path/to/key"
  # gpg:
  #   publicPath: "public.asc"
  #   privatePath: "private.asc"
  #   privatePassword: "password"
  # vault:
  #   address: "http://127.0.0.1:8200"
  #   token:
  #     token: "myroot"
  #   keyName: "testkey"
encoding:
  base64: true
hmacKey: "change-me-to-a-random-secret"
```

```go
var conf cryptfs.Config
if err := yaml.Unmarshal(data, &conf); err != nil { // or json.Unmarshal
    return err
}
fsys, err := cryptfs.FromConfig(conf)
if err != nil {
    return err
}
```

</details>

Once initialized you can perform open/read and write operations.

**Open**

`Open` returns the file as stored on disk. It does not decrypt. Use `ReadFile` or `Reveal` for plaintext.

```go
file, err := fsys.Open(path)
if err != nil {
    // handle error
}
```

**ReadFile**
```go
plaintext, err := fsys.ReadFile(path)
if err != nil {
    // handle error
}
```

**WriteFile**
```go
err := fsys.WriteFile(path, data, 0600)
if err != nil {
    // handle error
}
```

**Disfigure / Reveal**

`Disfigure` and `Reveal` encrypt and decrypt bytes in memory with the same format as `WriteFile` and `ReadFile`.

```go
encrypted, err := fsys.Disfigure([]byte("hello, world"))
if err != nil {
    // handle error
}

plaintext, err := fsys.Reveal(encrypted)
if err != nil {
    // handle error
}
```

### Streaming API (`stream.NewWriter` / `stream.NewReader`)

The `github.com/moov-io/cryptfs/stream` sub-package provides streaming encryption that works in fixed-size chunks (default 64KB), keeping memory usage bounded regardless of file size. This is ideal for use with cloud storage (e.g. `gocloud.dev/blob`) or any `io.Writer`/`io.Reader` pipeline.

The streaming format (CRFS) uses AES-GCM with per-file data keys, chunked encryption, and optional gzip compression. When using Vault, this enables **envelope encryption** — Vault generates and wraps data keys, and all data encryption happens locally. The master key never leaves Vault.

<details>
<summary>AES streaming</summary>

```go
import "github.com/moov-io/cryptfs/stream"

key := []byte("1234567812345678")
kp := stream.NewStaticKeyProvider(key)

// Encrypt
var buf bytes.Buffer
w, err := stream.NewWriter(&buf, kp, stream.WithCompression()) // compression is optional
if err != nil {
    // handle error
}
if _, err := io.Copy(w, sourceReader); err != nil {
    // handle error
}
if err := w.Close(); err != nil {
    // handle error
}

// Decrypt
r, err := stream.NewReader(bytes.NewReader(buf.Bytes()), kp)
if err != nil {
    // handle error
}
plaintext, err := io.ReadAll(r)
if err != nil {
    // handle error
}
if err := r.Close(); err != nil {
    // handle error
}
```

</details>

<details>
<summary>Vault envelope encryption</summary>

Each call to `stream.NewWriter` generates a fresh [data key](https://developer.hashicorp.com/vault/tutorials/encryption-as-a-service/eaas-transit#why-would-i-need-the-data-key) via Vault Transit — the plaintext key encrypts locally, and only the wrapped key is stored in the file header.

```go
import (
    "github.com/moov-io/cryptfs"
    "github.com/moov-io/cryptfs/stream"
)

vaultConf := cryptfs.VaultConfig{
    Address: "http://127.0.0.1:8200",
    Token: &cryptfs.TokenConfig{
        Token: os.Getenv("VAULT_TOKEN"),
    },
    // Kubernetes: &cryptfs.KubernetesConfig{Path: "/var/run/secrets/kubernetes.io/serviceaccount/token"},
    KeyName: "testkey", // name of the transit key
}

// Set up Vault key provider
kp, err := cryptfs.NewVaultKeyProvider(vaultConf)
if err != nil {
    // handle error
}

// Write — generates a Vault data key, encrypts locally
w, err := stream.NewWriter(destination, kp)
if err != nil {
    // handle error
}
if _, err := io.Copy(w, sourceReader); err != nil {
    // handle error
}
if err := w.Close(); err != nil {
    // handle error
}

// Read — unwraps the data key via Vault, decrypts locally
r, err := stream.NewReader(source, kp)
if err != nil {
    // handle error
}
plaintext, err := io.ReadAll(r)
if err != nil {
    // handle error
}
if err := r.Close(); err != nil {
    // handle error
}
```

Set `Address` and one auth method (`Token` or `Kubernetes`). `KeyName` is the name of a Vault Transit key. To set up Transit and create the key:

```
vault secrets enable transit
vault write -f transit/keys/testkey
```

The Vault token needs this policy (replace `testkey` with your key name):

```hcl
# Streaming envelope encryption (NewVaultKeyProvider)
path "transit/datakey/plaintext/testkey" {
  capabilities = ["update"]
}
path "transit/decrypt/testkey" {
  capabilities = ["update"]
}

# In-memory Vault encryption (NewVaultCryptor) also needs
path "transit/encrypt/testkey" {
  capabilities = ["update"]
}
```

</details>

<details>
<summary>Streaming write to a cloud bucket</summary>

```go
func (bs *bucketStorage) Save(ctx context.Context, path string, file fs.File) (retErr error) {
    bw, err := bs.bucket.NewWriter(ctx, path, nil)
    if err != nil {
        return err
    }
    defer func() {
        if err := bw.Close(); retErr == nil {
            retErr = err
        }
    }()

    ew, err := stream.NewWriter(bw, bs.keyProvider)
    if err != nil {
        return err
    }
    defer func() {
        if err := ew.Close(); retErr == nil {
            retErr = err
        }
    }()

    _, err = io.Copy(ew, file)
    return err
}
```

</details>

<details>
<summary>Streaming read from a cloud bucket</summary>

```go
func (bs *bucketStorage) Read(ctx context.Context, path string) (io.ReadCloser, error) {
    br, err := bs.bucket.NewReader(ctx, path, nil)
    if err != nil {
        return nil, err
    }

    dr, err := stream.NewReader(br, bs.keyProvider)
    if err != nil {
        br.Close()
        return nil, err
    }
    return dr, nil // Close() closes both dr and the underlying bucket reader
}
```

</details>

## Command Line

Moov offers a [command line tool](./cmd/cryptfs) for using this library as well. It's handy for operational debugging and testing.

## Running tests

The tests for the Vault cryptor need a Vault server on `localhost:8200` with root token `myroot` and a transit key named `testkey`. `make setup` starts this server with Docker Compose and `make teardown` stops it.

```
make setup
go test ./...
make teardown
```

Without Docker, run `go test -short ./...`. The `-short` flag skips the tests that need Vault.

## Getting help

 channel | info
 ------- | -------
Twitter [@moov](https://twitter.com/moov)	| You can follow Moov.io's Twitter feed to get updates on our project(s). You can also tweet us questions or just share blogs or stories.
[GitHub Issue](https://github.com/moov-io/cryptfs/issues/new) | If you are able to reproduce a problem please open a GitHub Issue under the specific project that caused the error.
[moov-io slack](https://slack.moov.io/) | Join our slack channel to have an interactive discussion about the development of the project.

## Supported and tested platforms

- 64-bit Linux (Ubuntu, Debian), macOS, and Windows

## Contributing

Yes please! Please review our [Contributing guide](https://github.com/moov-io/ach/blob/master/CONTRIBUTING.md) and [Code of Conduct](https://github.com/moov-io/ach/blob/master/CODE_OF_CONDUCT.md) to get started! Checkout our [issues for first time contributors](https://github.com/moov-io/cryptfs/contribute) for something to help out with.

This project uses [Go Modules](https://go.dev/blog/using-go-modules) and Go v1.26 or newer. See [Golang's install instructions](https://golang.org/doc/install) for help setting up Go. You can download the source code and we offer [tagged and released versions](https://github.com/moov-io/cryptfs/releases/latest) as well. We highly recommend you use a tagged release for production.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
