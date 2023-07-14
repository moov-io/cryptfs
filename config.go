package cryptfs

import (
	"fmt"
	"os"
)

type Config struct {
	Compression CompressionConfig `json:"compression" yaml:"compression"`
	Encryption  EncryptionConfig  `json:"encryption" yaml:"encryption"`
	Encoding    EncodingConfig    `json:"encoding" yaml:"encoding"`
}

type CompressionConfig struct {
	Gzip *GzipConfig `json:"gzip" yaml:"gzip"`
}

type GzipConfig struct {
	Level    int  `json:"level" yaml:"level"`
	Required bool `json:"required" yaml:"required"`
}

type EncryptionConfig struct {
	AES   *AESConfig   `json:"aes" yaml:"aes"`
	GPG   *GPGConfig   `json:"gpg" yaml:"gpg"`
	Vault *VaultConfig `json:"vault" yaml:"vault"`
}

type AESConfig struct {
	Key     string `json:"key" yaml:"yaml"`
	KeyPath string `json:"keyPath" yaml:"keyPath"`
}

type GPGConfig struct {
	PublicPath      string `json:"publicPath" yaml:"publicPath"`
	PrivatePath     string `json:"privatePath" yaml:"privatePath"`
	PrivatePassword string `json:"privatePassword" yaml:"privatePassword"`
}

type EncodingConfig struct {
	Base64 bool `json:"base64" yaml:"base64"`
}

func FromConfig(conf Config) (*FS, error) {
	var err error

	// Encryption
	cryptor := NoEncryption()
	switch {
	case conf.Encryption.AES != nil:
		var key []byte
		if len(conf.Encryption.AES.Key) > 0 {
			key = []byte(conf.Encryption.AES.Key)
		} else {
			key, err = os.ReadFile(conf.Encryption.AES.KeyPath)
			if err != nil {
				return nil, fmt.Errorf("reading AES key from %s: %w", conf.Encryption.AES.KeyPath, err)
			}
		}
		cryptor, err = NewAESCryptor(key)

	case conf.Encryption.GPG != nil:
		if conf.Encryption.GPG.PublicPath != "" && conf.Encryption.GPG.PrivatePath == "" {
			cryptor, err = NewGPGEncryptorFile(conf.Encryption.GPG.PublicPath)
		}

		password := []byte(conf.Encryption.GPG.PrivatePassword)
		if conf.Encryption.GPG.PublicPath == "" && conf.Encryption.GPG.PrivatePath != "" {
			cryptor, err = NewGPGDecryptorFile(conf.Encryption.GPG.PrivatePath, password)
		}
		if conf.Encryption.GPG.PublicPath != "" && conf.Encryption.GPG.PrivatePath != "" {
			cryptor, err = NewGPGCryptorFile(conf.Encryption.GPG.PublicPath, conf.Encryption.GPG.PrivatePath, password)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("cryptor from config: %w", err)
	}

	// Setup the FS
	fsys, err := New(cryptor)
	if err != nil {
		return nil, fmt.Errorf("cryptfs from config: %w", err)
	}

	// Compression
	if conf.Compression.Gzip != nil {
		compressor := Gzip()
		if conf.Compression.Gzip.Level > 0 {
			compressor = GzipLevel(conf.Compression.Gzip.Level)
		}
		if conf.Compression.Gzip.Required {
			compressor = GzipRequired(conf.Compression.Gzip.Level)
		}
		fsys.SetCompression(compressor)
	}

	// Encoding
	if conf.Encoding.Base64 {
		fsys.SetCoder(Base64())
	}

	return fsys, nil
}
