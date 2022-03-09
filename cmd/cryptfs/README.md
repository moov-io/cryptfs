## cryptfs

`cryptfs` offers a command line utility for encrypting / decrypting files.

### Install

```
go get github.com/moov-io/cryptfs/cmd/cryptfs
```

### Usage

```
$ cryptfs -help
Usage of cryptfs:
  -aes string
    	Configure AES encryption with the specified key. Can also be a filepath.
    	Prefix value with 'base64:' to decode key.
  -base64
    	Configure Base64 encoding
  -decrypt string
    	Filepath to load and attempt decryption
  -encrypt string
    	Filepath to load and attempt encryption
  -output string
    	Optional filepath to write final contents into
  -verbose
    	Enable verbose logging
```

#### Encryption

```
$ cryptfs -encrypt coder.go -verbose -aes 1234567887654321 -base64 -output foo.enc
2022/03/09 14:37:09 DEBUG Preparing foo.enc for output
```

#### Decryption

```
$ cryptfs -encrypt coder.go -verbose -aes 1234567887654321 -base64
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%
```

## Getting help

 channel | info
 ------- | -------
Twitter [@moov](https://twitter.com/moov) | You can follow Moov.io's Twitter feed to get updates on our project(s). You can also tweet us questions or just share blogs or stories.
[GitHub Issue](https://github.com/moov-io/cryptfs/issues/new) | If you are able to reproduce a problem please open a GitHub Issue under the specific project that caused the error.
[moov-io slack](https://slack.moov.io/) | Join our slack channel (`#infra`) to have an interactive discussion about the development of the project.

## Contributing

Yes please! Please review our [Contributing guide](CONTRIBUTING.md) and [Code of Conduct](https://github.com/moov-io/ach/blob/master/CODE_OF_CONDUCT.md) to get started! Checkout our [issues for first time contributors](https://github.com/moov-io/watchman/contribute) for something to help out with.

This project uses [Go Modules](https://github.com/golang/go/wiki/Modules) and uses Go v1.14 or higher. See [Golang's install instructions](https://golang.org/doc/install) for help setting up Go. You can download the source code and we offer [tagged and released versions](https://github.com/moov-io/ach/releases/latest) as well. We highly recommend you use a tagged release for production.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.
