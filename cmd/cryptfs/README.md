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
$ cryptfs -decrypt foo.enc -verbose -aes 1234567887654321 -base64
... (output)
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
