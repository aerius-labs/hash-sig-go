package prf

import (
	"encoding/binary"
	"io"
	
	"golang.org/x/crypto/sha3"
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/aerius-labs/hash-sig-go/th"
)

// ShakePRFtoField implements a PRF using SHAKE128 that outputs field elements
// Matches Rust's ShakePRFtoF implementation
type ShakePRFtoField struct {
	keyLen       int
	outputLenFE  int // Output length in field elements
}

// NewShakePRFtoField creates a new SHAKE-based PRF outputting field elements
func NewShakePRFtoField(keyLen int, outputLenFE int) *ShakePRFtoField {
	return &ShakePRFtoField{
		keyLen:      keyLen,
		outputLenFE: outputLenFE,
	}
}

// KeyGen generates a new PRF key
func (p *ShakePRFtoField) KeyGen(rng io.Reader) []byte {
	key := make([]byte, p.keyLen)
	if _, err := io.ReadFull(rng, key); err != nil {
		panic("failed to generate PRF key: " + err.Error())
	}
	return key
}

// Domain separator for Shake PRF to Field - must match Rust
var shakePRFDomainSep = []byte{
	0xae, 0xae, 0x22, 0xff, 0x00, 0x01, 0xfa, 0xff,
	0x21, 0xaf, 0x12, 0x00, 0x01, 0x11, 0xff, 0x00,
}

// Apply computes PRF(key, epoch, chainIndex) and returns field elements
func (p *ShakePRFtoField) Apply(key []byte, epoch uint32, chainIndex uint64) th.Domain {
	// Use SHAKE128 to match Rust implementation
	shake := sha3.NewShake128()
	
	// Write domain_sep || key || epoch || chainIndex (matches Rust order)
	shake.Write(shakePRFDomainSep)
	shake.Write(key)
	
	epochBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(epochBytes, epoch)
	shake.Write(epochBytes)
	
	chainBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(chainBytes, chainIndex)
	shake.Write(chainBytes)
	
	// Generate field elements using modular reduction (matches Rust)
	// Rust uses 8 bytes per field element and takes mod
	const bytesPerFE = 8
	prfOutput := make([]byte, bytesPerFE*p.outputLenFE)
	shake.Read(prfOutput)
	
	result := make([]byte, 0, p.outputLenFE*4)
	for i := 0; i < p.outputLenFE; i++ {
		chunkStart := i * bytesPerFE
		chunkEnd := chunkStart + bytesPerFE
		
		// Convert bytes to uint64 (big-endian) and take mod
		val := binary.BigEndian.Uint64(prfOutput[chunkStart:chunkEnd])
		val = val % 2013265921 // BabyBear prime
		
		var elem babybear.Element
		elem.SetUint64(val)
		b := elem.Bytes()
		result = append(result, b[:]...)
	}
	
	return result
}

// OutputLen returns the output length in bytes
func (p *ShakePRFtoField) OutputLen() int {
	return p.outputLenFE * 4 // 4 bytes per field element
}