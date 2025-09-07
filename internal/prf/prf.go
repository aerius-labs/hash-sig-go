package prf

import (
	"encoding/binary"
	"io"
	
	"golang.org/x/crypto/sha3"
	"github.com/aerius-labs/hash-sig-go/th"
)

// PRF defines the interface for a pseudorandom function
type PRF interface {
	// KeyGen generates a new PRF key
	KeyGen(rng io.Reader) []byte
	
	// Apply computes PRF(key, epoch, chainIndex)
	Apply(key []byte, epoch uint32, chainIndex uint64) th.Domain
	
	// OutputLen returns the output length in bytes
	OutputLen() int
}

// Domain separator for PRF - must match Rust implementation
var prfDomainSep = []byte{
	0x00, 0x01, 0x12, 0xff, 0x00, 0x01, 0xfa, 0xff,
	0x00, 0xaf, 0x12, 0xff, 0x01, 0xfa, 0xff, 0x00,
}

// SHA3PRF implements a PRF using SHA3
type SHA3PRF struct {
	keyLen    int
	outputLen int
}

// NewSHA3PRF creates a new SHA3-based PRF
func NewSHA3PRF(keyLen, outputLen int) *SHA3PRF {
	return &SHA3PRF{
		keyLen:    keyLen,
		outputLen: outputLen,
	}
}

// KeyGen generates a new PRF key
func (p *SHA3PRF) KeyGen(rng io.Reader) []byte {
	key := make([]byte, p.keyLen)
	if _, err := io.ReadFull(rng, key); err != nil {
		panic("failed to generate PRF key: " + err.Error())
	}
	return key
}

// Apply computes PRF(key, epoch, chainIndex)
func (p *SHA3PRF) Apply(key []byte, epoch uint32, chainIndex uint64) th.Domain {
	h := sha3.New256()
	
	// Write domain separator || key || epoch || chainIndex
	h.Write(prfDomainSep)
	h.Write(key)
	epochBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(epochBytes, epoch)
	h.Write(epochBytes)
	
	chainBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(chainBytes, chainIndex)
	h.Write(chainBytes)
	
	// Get hash and truncate to output length
	fullHash := h.Sum(nil)
	if len(fullHash) > p.outputLen {
		return fullHash[:p.outputLen]
	}
	return fullHash
}

// OutputLen returns the output length in bytes
func (p *SHA3PRF) OutputLen() int {
	return p.outputLen
}