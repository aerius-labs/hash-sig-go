# hashsig-go

Go implementation of generalized XMSS with tweakable hashes and incomparable encodings (Winternitz & Target-Sum variants).

This is a port of the Rust implementation at [b-wagn/hash-sig](https://github.com/b-wagn/hash-sig), implementing the cryptographic constructions from:
- "Hash-Based Multi-Signatures for Post-Quantum Ethereum" [DKKW25a]
- "LeanSig for Post-Quantum Ethereum" [DKKW25b]

## Features

- **Generalized XMSS** (Construction 3) signature scheme
- **Tweakable hash functions** with SHA-3 backend (Section 7.2)
- **Incomparable encodings**:
  - Winternitz encoding (Construction 5)
  - Target-Sum Winternitz encoding (Construction 6)
- **Merkle tree** construction (Construction 1)
- **Hash chains** (Construction 2)
- Parallel computation for improved performance
- Full test coverage with parity to Rust implementation

## Installation

```bash
go get github.com/aerius-labs/hash-sig-go
```

## Usage

### Library Usage

```go
package main

import (
    "crypto/rand"
    "fmt"
    
    "github.com/aerius-labs/hash-sig-go/encoding/winternitz"
    "github.com/aerius-labs/hash-sig-go/internal/prf"
    "github.com/aerius-labs/hash-sig-go/th/sha3"
    "github.com/aerius-labs/hash-sig-go/xmss"
)

func main() {
    // Setup components
    prfInstance := prf.NewSHA3PRF(24, 24)
    thInstance := sha3.NewSHA3TweakableHash(24, 24)
    mhInstance := sha3.NewSHA3MessageHash(24, 24, 48, 4)
    
    // Create Winternitz encoding
    checksumLen := winternitz.ComputeChecksumLength(48, 4)
    encInstance := winternitz.NewWinternitzEncoding(mhInstance, 4, checksumLen)
    
    // Create XMSS with log lifetime = 8 (256 epochs)
    xmssInstance := xmss.NewGeneralizedXMSS(prfInstance, encInstance, thInstance, 8)
    
    // Generate keys
    pk, sk := xmssInstance.KeyGen(rand.Reader, 0, 256)
    
    // Sign a message
    message := make([]byte, 32)
    rand.Read(message)
    
    sig, err := xmssInstance.Sign(rand.Reader, sk, 0, message)
    if err != nil {
        panic(err)
    }
    
    // Verify signature
    valid := xmssInstance.Verify(pk, 0, message, sig)
    fmt.Printf("Signature valid: %v\n", valid)
}
```

### CLI Usage

Build the CLI tool:
```bash
go build ./cmd/hashsig-cli
```

Generate keys:
```bash
./hashsig-cli keygen -out mykey
```

Sign a message:
```bash
./hashsig-cli sign -sk mykey.sk -epoch 0 -msg <hex_message> -out sig.bin
```

Verify a signature:
```bash
./hashsig-cli verify -pk mykey.pk -epoch 0 -msg <hex_message> -sig sig.bin
```

## Testing

Run all tests:
```bash
go test ./...
```

Run benchmarks:
```bash
go test -bench=. ./xmss
```

## Parameters

### Winternitz Encoding
- Chunk size w ∈ {1,2,4,8} bits
- Checksum length n₁ = ⌊log_{2^w}(n₀(2^w−1))⌋ + 1
- Always succeeds (no retries needed)

### Target-Sum Winternitz
- Target sum T = ⌈δ·v·(2^w−1)/2⌉ with δ ∈ {1.0, 1.1}
- May require retries (probabilistic encoding)
- Reduces verifier hashing cost

## References

- [DKKW25a] "Hash-Based Multi-Signatures for Post-Quantum Ethereum" https://eprint.iacr.org/2025/055.pdf
- [DKKW25b] "LeanSig for Post-Quantum Ethereum" https://eprint.iacr.org/2025/1332.pdf

## License
Apache Version 2.0.
