# Security Model

This document describes the cryptographic design of the `cryptfs/stream` package for security review and PCI audit purposes.

## Encryption Algorithm

All data is encrypted with **AES-GCM** (Galois/Counter Mode), an AEAD cipher that provides both confidentiality and integrity. The implementation uses Go's standard `crypto/aes` and `crypto/cipher` packages.

Supported key sizes: AES-128 (16 bytes), AES-192 (24 bytes), AES-256 (32 bytes).

## Per-File Data Keys

Every file is encrypted with a unique data key. When using Vault Transit, a fresh data key is generated per `NewWriter` call:

1. The library requests a new data key from Vault Transit (`/transit/datakey/plaintext/{keyName}`).
2. Vault returns the plaintext key (used locally for AES-GCM) and a wrapped copy (ciphertext encrypted under the Vault master key).
3. Only the **wrapped key** is stored in the file header. The plaintext key lives in process memory during encryption and is never persisted.
4. On decryption, the wrapped key is sent back to Vault Transit (`/transit/decrypt/{keyName}`) to recover the plaintext key.

The master key never leaves Vault. Vault handles key rotation, access policy, and audit logging.

## Chunked Encryption

Data is split into fixed-size chunks (default 64 KB of plaintext) and each chunk is independently encrypted with AES-GCM. This allows streaming encryption and decryption without buffering the entire file.

Each encrypted chunk consists of:

| Field | Size |
|---|---|
| Chunk length | 4 bytes (big-endian) |
| Nonce | 12 bytes |
| Ciphertext | equal to plaintext length |
| GCM authentication tag | 16 bytes |

The stream ends with a 4-byte zero end marker (`0x00000000`).

## Nonce Construction

Each chunk nonce is 12 bytes, the standard AES-GCM nonce size, constructed from two parts:

| Component | Size | Source |
|---|---|---|
| Random prefix | 7 bytes | `crypto/rand`, generated once per file |
| Counter | 5 bytes | Big-endian, starts at 0, increments per chunk |

This design prevents nonce reuse through two independent mechanisms:

- The **random prefix** ensures uniqueness across files encrypted with the same key.
- The **incrementing counter** ensures uniqueness across chunks within a single file.
- A hard limit at 2^40 chunks prevents counter wraparound. At 64 KB per chunk this allows up to 64 PB per file before the limit is reached.

## Integrity Guarantees (AEAD)

AES-GCM is an authenticated encryption scheme. Every chunk carries a 16-byte authentication tag that is verified on decryption. Any modification to the ciphertext, nonce, or associated data causes decryption to fail.

**Header binding.** The serialized file header (magic, version, flags, nonce prefix, wrapped key) is passed as Additional Authenticated Data (AAD) when encrypting and decrypting chunk 0. This cryptographically binds the header to the data so that tampering with any header field (flags, nonce prefix, wrapped key) causes authentication failure.

**Chunk ordering.** Each chunk's nonce embeds a counter that must match the expected sequence. Reordering, duplicating, or dropping chunks is detected because the nonce will not match.

**Truncation.** A missing end marker after the last chunk is detected as an unexpected end-of-stream error.

## File Format (CRFS)

```
[Header]
  Magic:          4 bytes ("CRFS")
  Version:        1 byte  (0x01)
  Flags:          1 byte  (bit 0 = gzip compression)
  Nonce prefix:   7 bytes (random)
  Wrapped key len: 2 bytes (big-endian)
  Wrapped key:    variable (Vault ciphertext, empty for static keys)

[Chunks]
  Chunk length:   4 bytes (big-endian)
  Nonce:          12 bytes
  Ciphertext+Tag: variable
  ...repeated...

[End marker]
  0x00000000:     4 bytes
```

## Optional Compression

When enabled, plaintext is gzip-compressed before encryption. The compression flag is stored in the header Flags byte and is integrity-protected through the AAD binding described above.

## Error Handling

Both `Writer` and `Reader` implement use-after-close and sticky-error guards. Once closed or in an error state, all subsequent operations return an error to prevent writing data past the end marker or reading from a closed source.
