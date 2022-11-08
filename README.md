[![Moov Banner Logo](https://user-images.githubusercontent.com/20115216/104214617-885b3c80-53ec-11eb-8ce0-9fc745fb5bfc.png)](https://github.com/moov-io)

<!--
<p align="center">
  <a href="https://moov-io.github.io/ach/">Project Documentation</a>
  ·
  <a href="https://moov-io.github.io/ach/api/#get-/files">API Endpoints</a>
  ·
  <a href="https://moov.io/blog/education/ach-api-guide/">API Guide</a>
  ·
  <a href="https://slack.moov.io/">Community</a>
  ·
  <a href="https://moov.io/blog/">Blog</a>
  <br>
  <br>
</p>
-->

[![GoDoc](https://godoc.org/github.com/moov-io/cryptfs?status.svg)](https://godoc.org/github.com/moov-io/cryptfs)
[![Build Status](https://github.com/moov-io/cryptfs/workflows/Go/badge.svg)](https://github.com/moov-io/cryptfs/actions)
[![Coverage Status](https://codecov.io/gh/moov-io/cryptfs/branch/master/graph/badge.svg)](https://codecov.io/gh/moov-io/cryptfs)
[![Go Report Card](https://goreportcard.com/badge/github.com/moov-io/cryptfs)](https://goreportcard.com/report/github.com/moov-io/cryptfs)
[![Repo Size](https://img.shields.io/github/languages/code-size/moov-io/cryptfs?label=project%20size)](https://github.com/moov-io/cryptfs)
[![Apache 2 License](https://img.shields.io/badge/license-Apache2-blue.svg)](https://raw.githubusercontent.com/moov-io/cryptfs/master/LICENSE)
[![Slack Channel](https://slack.moov.io/badge.svg?bg=e01563&fgColor=fffff)](https://slack.moov.io/)
[![GitHub Stars](https://img.shields.io/github/stars/moov-io/cryptfs)](https://github.com/moov-io/cryptfs)
[![Twitter](https://img.shields.io/twitter/follow/moov?style=social)](https://twitter.com/moov?lang=en)

# moov-io/cryptfs
Moov's mission is to give developers an easy way to create and integrate bank processing into their own software products. Our open source projects are each focused on solving a single responsibility in financial services and designed around performance, scalability, and ease of use.

cryptfs implements Go's [`io/fs.FS`](https://pkg.go.dev/io/fs#FS) interface for interacting with the local filesystem to transparently encrypt/decrypt files. This is useful as a library because it offers applications a well tested routine for keeping data protected.

## Project Status

cryptfs is included in multiple open-source projects Moov offers and is used in production environments. Please star the project if you are interested in its progress. If you find any bugs or desire additional encryption/encoding algorithms we would appreciate an issue or pull request. Thanks!

## Usage

Cryptfs supports AES and GPG for encryption and Base64 (Standard Raw) encoding. Currently cryptfs is usable as a Go library in your applications. This needs to be initialized prior to reading or writing any files.

<details>
<summary>AES Cryptor</summary>

```go
key := []byte("1234567812345678")) // insecure key

fsys, err := cryptfs.FromCryptor(cryptfs.NewAESCryptor(key))
if err != nil {
    // do something
}

fsys.SetCoder(cryptfs.Base64()) // optional, default is the raw bytes
```

</details>

<details>
<summary>GPG Cryptor</summary>

```go
fsys, err := cryptfs.FromCryptor(cryptfs.NewGPGCryptorFile(publicKeyPath, privateKeyPath, password))
if err != nil {
    // do something
}

fsys.SetCoder(cryptfs.Base64()) // optional, default is the raw bytes
```

</details>

Once initialized you can perform open/read and write operations.

**Open**
```go
file, err := fsys.Open(path)
if err != nil {
    // do something
}
```

**ReadFile**
```go
plaintext, err := fsys.ReadFile(path)
if err != nil {
    // do something
}
```

**WriteFile**
```go
err := fsys.WriteFile(path, data, 0600)
if err != nil {
    // do something
}
```

## Command Line

Moov offers a [command line tool](./cmd/cryptfs) for using this library as well. It's handy for operational debugging and testing.

## Getting help

 channel | info
 ------- | -------
Twitter [@moov](https://twitter.com/moov)	| You can follow Moov.io's Twitter feed to get updates on our project(s). You can also tweet us questions or just share blogs or stories.
[GitHub Issue](https://github.com/moov-io/cryptfs/issues/new) | If you are able to reproduce a problem please open a GitHub Issue under the specific project that caused the error.
[moov-io slack](https://slack.moov.io/) | Join our slack channel to have an interactive discussion about the development of the project.

## Supported and tested platforms

- 64-bit Linux (Ubuntu, Debian), macOS, and Windows

## Contributing

Yes please! Please review our [Contributing guide](CONTRIBUTING.md) and [Code of Conduct](https://github.com/moov-io/ach/blob/master/CODE_OF_CONDUCT.md) to get started! Checkout our [issues for first time contributors](https://github.com/moov-io/watchman/contribute) for something to help out with.

This project uses [Go Modules](https://go.dev/blog/using-go-modules) and Go v1.18 or newer. See [Golang's install instructions](https://golang.org/doc/install) for help setting up Go. You can download the source code and we offer [tagged and released versions](https://github.com/moov-io/ach/releases/latest) as well. We highly recommend you use a tagged release for production.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
