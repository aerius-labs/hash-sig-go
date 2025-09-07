package th

import (
	"crypto/rand"
	"io"
)

// MessageLength is the fixed length of messages to sign (32 bytes)
const MessageLength = 32

// Tweak separator constants for domain separation
const (
	TweakSeparatorChainHash   = 0x00
	TweakSeparatorTreeHash    = 0x01
	TweakSeparatorMessageHash = 0x02
)

// Tweak represents a tweak value for domain separation
type Tweak []byte

// Params represents public parameters for the tweakable hash
type Params []byte

// Domain represents a hash output domain element
type Domain []byte

// TweakableHash defines the interface for a tweakable hash function
// following Construction 1 from the paper
type TweakableHash interface {
	// RandParameter generates a random public parameter
	RandParameter(rng io.Reader) Params
	
	// RandDomain generates a random domain element (for testing)
	RandDomain(rng io.Reader) Domain
	
	// TreeTweak returns a tweak for Merkle tree operations
	// Implements Eq. (18) from the paper
	TreeTweak(level uint8, posInLevel uint32) Tweak
	
	// ChainTweak returns a tweak for hash chain operations
	// Implements Eq. (17) from the paper
	ChainTweak(epoch uint32, chainIndex uint8, posInChain uint8) Tweak
	
	// Apply computes the tweakable hash: H(P, T, M)
	Apply(parameter Params, tweak Tweak, message []Domain) Domain
	
	// OutputLen returns the output length in bytes
	OutputLen() int
	
	// ParameterLen returns the parameter length in bytes
	ParameterLen() int
}

// MessageHasher extends TweakableHash for message hashing operations
type MessageHasher interface {
	// DigestChunks returns ℓ chunks, each w bits (packed), as required by the encoding
	// Implements Thmsg from Section 7
	DigestChunks(P Params, T Tweak, msg []byte, rho []byte, w, ell int) ([]uint32, error)
	
	// RandRandomness generates randomness for message encoding
	RandRandomness(rng io.Reader) []byte
}

// Chain implements hash chains (Construction 2 from the paper)
// Walks a chain for 'steps' starting from 'start' at position 'startPosInChain'
func Chain(th TweakableHash, parameter Params, epoch uint32, chainIndex uint8, 
	startPosInChain uint8, steps int, start Domain) Domain {
	
	current := make(Domain, len(start))
	copy(current, start)
	
	for j := 0; j < steps; j++ {
		tweak := th.ChainTweak(epoch, chainIndex, startPosInChain+uint8(j)+1)
		current = th.Apply(parameter, tweak, []Domain{current})
	}
	
	return current
}

// Helper to generate random bytes
func randBytes(rng io.Reader, n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rng, b); err != nil {
		// In production, handle this error properly
		if rng == rand.Reader {
			panic("failed to read from crypto/rand: " + err.Error())
		}
		// For testing with deterministic RNG
		panic("failed to read from RNG: " + err.Error())
	}
	return b
}