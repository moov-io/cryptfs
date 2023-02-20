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

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/moov-io/cryptfs"
)

var (
	flagDecrypt = flag.String("decrypt", "", "Filepath to load and attempt decryption")
	flagEncrypt = flag.String("encrypt", "", "Filepath to load and attempt encryption")
	flagOutput  = flag.String("output", "", "Optional filepath to write final contents into")
	flagVerbose = flag.Bool("verbose", false, "Enable verbose logging")

	// Coder flags
	flagBase64 = flag.Bool("base64", false, "Configure Base64 encoding")

	// Cryptor flags
	flagAES = flag.String("aes", os.Getenv("AES_KEY"), strings.TrimSpace(`
Configure AES encryption with the specified key. Can also be a filepath.
Prefix value with 'base64:' to decode key.
`))
)

func main() {
	flag.Parse()

	output := setupOutput(*flagOutput)
	defer output.Close()

	// Determine what action to take
	switch {
	case *flagDecrypt != "":
		cc, err := setupCryptfs()
		if err != nil {
			log.Fatalf("ERROR creating cryptfs: %v", err)
		}
		out, err := decrypt(cc, *flagDecrypt)
		if err != nil {
			log.Fatalf("ERROR during decryption: %v", err)
		}
		if _, err := output.Write(out); err != nil {
			log.Fatalf("ERROR writing output: %v", err)
		}

	case *flagEncrypt != "":
		cc, err := setupCryptfs()
		if err != nil {
			log.Fatalf("ERROR creating cryptfs: %v", err)
		}
		out, err := encrypt(cc, *flagEncrypt)
		if err != nil {
			log.Fatalf("ERROR during encryption: %v", err)
		}
		if _, err := output.Write(out); err != nil {
			log.Fatalf("ERROR writing output: %v", err)
		}

	default:
		log.Fatalf("ERROR: no action specified")
	}
}

type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error {
	return nil
}

func setupOutput(flagValue string) io.WriteCloser {
	if flagValue == "" {
		return nopCloser{Writer: os.Stdout}
	}

	fd, err := os.Create(flagValue)
	if err != nil {
		log.Fatalf("ERROR opening %s -- %v", flagValue, err)
	}
	if *flagVerbose {
		log.Printf("DEBUG Preparing %s for output", fd.Name())
	}
	return fd
}

const base64EncodedPrefix = "base64:"

func setupCryptfs() (*cryptfs.FS, error) {
	var cc cryptfs.Cryptor
	var err error

	switch {
	case *flagAES != "":
		cc, err = openAESCryptor(*flagAES)
	}
	if err != nil {
		return nil, err
	}

	fs, err := cryptfs.New(cc)
	if err != nil {
		return nil, err
	}

	switch {
	case *flagBase64:
		fs.SetCoder(cryptfs.Base64())
	}

	return fs, nil
}

func openAESCryptor(pathOrValue string) (*cryptfs.AESCryptor, error) {
	data, err := readFile(pathOrValue)
	if err != nil {
		return nil, fmt.Errorf("AES key decode: %v", err)
	}
	fmt.Printf("data: %q\n", data)

	// Optionally decode base64 data
	if strings.HasPrefix(data, base64EncodedPrefix) {
		data = strings.TrimPrefix(data, base64EncodedPrefix)

		key, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, fmt.Errorf("decoding AES key: %v", err)
		}
		return cryptfs.NewAESCryptor(key)
	}

	return cryptfs.NewAESCryptor([]byte(data))
}

// readFile will return the contents of pathOrValue on the local filesystem
// or return pathOrValue directly.
func readFile(pathOrValue string) (string, error) {
	if _, err := os.Stat(pathOrValue); err == nil {
		bs, err := os.ReadFile(pathOrValue)
		if err != nil {
			return "", fmt.Errorf("opening %s failed: %v", pathOrValue, err)
		}
		return string(bs), nil
	}
	return pathOrValue, nil
}

func decrypt(cc *cryptfs.FS, path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s -- %v", path, err)
	}
	return cc.Reveal(raw)
}

func encrypt(cc *cryptfs.FS, path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s -- %v", path, err)
	}
	return cc.Disfigure(raw)
}
