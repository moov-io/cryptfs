package cryptfs

// DataKey holds a plaintext AES key and its wrapped (encrypted) form.
// For direct AES (staticKeyProvider), WrappedKey is nil.
// For Vault envelope encryption, WrappedKey is the Vault-encrypted data key.
type DataKey struct {
	Plaintext  []byte // raw AES key (16/24/32 bytes)
	WrappedKey []byte // opaque ciphertext for header; nil for direct AES
}

// KeyProvider generates and unwraps per-file data encryption keys.
type KeyProvider interface {
	GenerateKey() (*DataKey, error)
	UnwrapKey(wrappedKey []byte) ([]byte, error)
}

// NewStaticKeyProvider returns a KeyProvider that always uses the given AES key.
func NewStaticKeyProvider(key []byte) KeyProvider {
	cp := make([]byte, len(key))
	copy(cp, key)
	return &staticKeyProvider{key: cp}
}

type staticKeyProvider struct {
	key []byte
}

func (p *staticKeyProvider) GenerateKey() (*DataKey, error) {
	return &DataKey{Plaintext: p.key}, nil
}

func (p *staticKeyProvider) UnwrapKey(_ []byte) ([]byte, error) {
	return p.key, nil
}
