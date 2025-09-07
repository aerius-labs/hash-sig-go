package message_hash

import (
	"io"
	
	"golang.org/x/crypto/sha3"
	"github.com/aerius-labs/hash-sig-go/internal/bitutil"
	"github.com/aerius-labs/hash-sig-go/th"
	"github.com/aerius-labs/hash-sig-go/tweak"
)

// SHA3MessageHash implements message hashing using SHA3
// Following Section 7.2 of the paper for Thmsg
type SHA3MessageHash struct {
	parameterLen int
	randomnessLen int
	dimension    int  // number of chunks (v or n₀)
	chunkSize    int  // w in bits
}

// NewSHA3MessageHash creates a new SHA3-based message hash
func NewSHA3MessageHash(parameterLen, randomnessLen, dimension, chunkSize int) *SHA3MessageHash {
	if chunkSize != 1 && chunkSize != 2 && chunkSize != 4 && chunkSize != 8 {
		panic("chunk size must be 1, 2, 4, or 8")
	}
	if dimension > 256 {
		panic("dimension must be <= 256")
	}
	return &SHA3MessageHash{
		parameterLen:  parameterLen,
		randomnessLen: randomnessLen,
		dimension:     dimension,
		chunkSize:     chunkSize,
	}
}

// Common configurations
func NewSHA3MessageHash192x3() *SHA3MessageHash {
	// 24 byte param, 24 byte randomness, 48 chunks of 4 bits each
	return NewSHA3MessageHash(24, 24, 48, 4)
}

// RandRandomness generates randomness for message encoding
func (s *SHA3MessageHash) RandRandomness(rng io.Reader) []byte {
	r := make([]byte, s.randomnessLen)
	if _, err := io.ReadFull(rng, r); err != nil {
		panic("failed to generate randomness: " + err.Error())
	}
	return r
}

// Apply implements message hashing
// Returns chunks as uint8 values (each chunk is w bits, stored in a uint8)
func (s *SHA3MessageHash) Apply(parameter th.Params, epoch uint32, randomness []byte, message []byte) []uint8 {
	// Create message tweak
	msgTweak := tweak.MessageTweak(epoch)
	
	// Compute Thmsg: Truncate_(ℓ·w)_bits(SHA3(R||P||T||M))
	h := sha3.New256()
	h.Write(randomness)
	h.Write(parameter)
	h.Write(msgTweak)
	h.Write(message)
	
	fullHash := h.Sum(nil)
	
	// Truncate to exactly dimension * chunkSize bits
	numBits := s.dimension * s.chunkSize
	truncated := bitutil.TruncateBits(fullHash, numBits)
	
	// Split into w-bit chunks
	chunks, err := bitutil.BytesToChunks(truncated, s.chunkSize)
	if err != nil {
		panic("failed to split into chunks: " + err.Error())
	}
	
	// Ensure we have exactly dimension chunks
	if len(chunks) > s.dimension {
		chunks = chunks[:s.dimension]
	}
	
	return chunks
}

// Dimension returns the number of chunks
func (s *SHA3MessageHash) Dimension() int {
	return s.dimension
}

// Base returns 2^w
func (s *SHA3MessageHash) Base() int {
	return 1 << s.chunkSize
}

// ChunkSize returns w
func (s *SHA3MessageHash) ChunkSize() int {
	return s.chunkSize
}

// Hash implements the MessageHash interface
func (s *SHA3MessageHash) Hash(params th.Params, msg []byte, rand []byte, epoch uint32) []byte {
	return s.Apply(params, epoch, rand, msg)
}

// OutputLen returns the output length in bytes
func (s *SHA3MessageHash) OutputLen() int {
	return s.dimension
}

// RandLen returns the randomness length in bytes
func (s *SHA3MessageHash) RandLen() int {
	return s.randomnessLen
}