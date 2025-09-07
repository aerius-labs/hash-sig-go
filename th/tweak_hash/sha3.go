package tweak_hash

import (
	"io"
	
	"golang.org/x/crypto/sha3"
	"github.com/aerius-labs/hash-sig-go/th"
	"github.com/aerius-labs/hash-sig-go/tweak"
)

// SHA3TweakableHash implements tweakable hash using SHA3
// Following Section 7.2 of the paper
type SHA3TweakableHash struct {
	parameterLen int
	hashLen      int
}

// NewSHA3TweakableHash creates a new SHA3-based tweakable hash
func NewSHA3TweakableHash(parameterLen, hashLen int) *SHA3TweakableHash {
	if parameterLen > 255 || hashLen > 255 {
		panic("parameter and hash lengths must be <= 255 bytes")
	}
	return &SHA3TweakableHash{
		parameterLen: parameterLen,
		hashLen:      hashLen,
	}
}

// Common configurations
func NewSHA3_128_192() *SHA3TweakableHash { return NewSHA3TweakableHash(16, 24) }
func NewSHA3_192_192() *SHA3TweakableHash { return NewSHA3TweakableHash(24, 24) }

// RandParameter generates a random public parameter
func (s *SHA3TweakableHash) RandParameter(rng io.Reader) th.Params {
	p := make([]byte, s.parameterLen)
	if _, err := io.ReadFull(rng, p); err != nil {
		panic("failed to generate random parameter: " + err.Error())
	}
	return p
}

// RandDomain generates a random domain element
func (s *SHA3TweakableHash) RandDomain(rng io.Reader) th.Domain {
	d := make([]byte, s.hashLen)
	if _, err := io.ReadFull(rng, d); err != nil {
		panic("failed to generate random domain: " + err.Error())
	}
	return d
}

// TreeTweak returns a tweak for Merkle tree operations
func (s *SHA3TweakableHash) TreeTweak(level uint8, posInLevel uint32) th.Tweak {
	return tweak.TreeTweak(level, posInLevel)
}

// ChainTweak returns a tweak for hash chain operations
func (s *SHA3TweakableHash) ChainTweak(epoch uint32, chainIndex uint8, posInChain uint8) th.Tweak {
	return tweak.ChainTweak(epoch, chainIndex, posInChain)
}

// Apply computes Th: Truncate_n_bits(SHA3(P||T||M))
func (s *SHA3TweakableHash) Apply(parameter th.Params, tweak th.Tweak, message []th.Domain) th.Domain {
	h := sha3.New256()
	
	// Write P || T || M
	h.Write(parameter)
	h.Write(tweak)
	for _, m := range message {
		h.Write(m)
	}
	
	// Get full hash and truncate to hashLen bytes
	fullHash := h.Sum(nil)
	return truncateBytes(fullHash, s.hashLen)
}

// OutputLen returns the output length in bytes
func (s *SHA3TweakableHash) OutputLen() int {
	return s.hashLen
}

// ParameterLen returns the parameter length in bytes
func (s *SHA3TweakableHash) ParameterLen() int {
	return s.parameterLen
}

// truncateBytes truncates a byte slice to n bytes
func truncateBytes(data []byte, n int) []byte {
	if len(data) <= n {
		return data
	}
	return data[:n]
}