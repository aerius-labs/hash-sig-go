// Package poseidon implements Poseidon-based tweakable hash
package tweak_hash

import (
	"encoding/binary"
	"io"
	
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/aerius-labs/hash-sig-go/poseidon"
	"github.com/aerius-labs/hash-sig-go/th"
)

const (
	// Domain separators matching Rust
	TweakSeparatorChainHash   = 0x00
	TweakSeparatorTreeHash    = 0x01
	TweakSeparatorMessageHash = 0x02
	
	// Widths for different operations
	ChainCompressionWidth = 16
	MergeCompressionWidth = 24
	
	// Domain parameters length
	DomainParametersLength = 4
	
	// BabyBear prime
	P = 2013265921
)

// PoseidonTweakHash implements tweakable hash using Poseidon2
type PoseidonTweakHash struct {
	parameterLen int
	hashLen      int
	tweakLen     int
	capacity     int
	numChunks    int
}

// NewPoseidonTweakHash creates a new Poseidon tweakable hash
func NewPoseidonTweakHash(parameterLen, hashLen, tweakLen, capacity, numChunks int) *PoseidonTweakHash {
	return &PoseidonTweakHash{
		parameterLen: parameterLen,
		hashLen:      hashLen,
		tweakLen:     tweakLen,
		capacity:     capacity,
		numChunks:    numChunks,
	}
}

// RandParameter generates random parameters
func (p *PoseidonTweakHash) RandParameter(rng io.Reader) th.Params {
	params := make([]byte, p.parameterLen*4) // 4 bytes per field element
	if _, err := io.ReadFull(rng, params); err != nil {
		panic("failed to generate parameters")
	}
	return params
}

// Apply computes the tweakable hash
func (p *PoseidonTweakHash) Apply(params th.Params, tweak th.Tweak, data []th.Domain) th.Domain {
	// Convert parameters to field elements
	paramFields := bytesToFieldElements(params, p.parameterLen)
	
	// Convert tweak to field elements
	tweakFields := p.tweakToFieldElements(tweak)
	
	// Convert data to field elements
	var dataFields []babybear.Element
	for _, d := range data {
		dataFields = append(dataFields, bytesToFieldElements(d, p.hashLen)...)
	}
	
	// Compute capacity value as hash of params and tweak
	capacityValue := p.computeCapacityValue(paramFields, tweakFields)
	
	// Apply sponge construction
	result := p.poseidonSponge(capacityValue, dataFields)
	
	// Convert back to bytes
	return fieldElementsToBytes(result)
}

// TreeTweak creates a tree tweak
func (p *PoseidonTweakHash) TreeTweak(level uint8, posInLevel uint32) th.Tweak {
	tweak := make([]byte, 0, 9)
	tweak = append(tweak, TweakSeparatorTreeHash)
	
	// Pack as: (level << 40) | (posInLevel << 8) | separator
	// But we'll store it more simply for Go
	levelBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(levelBytes, uint64(level)<<40 | uint64(posInLevel)<<8 | TweakSeparatorTreeHash)
	return levelBytes
}

// ChainTweak creates a chain tweak
func (p *PoseidonTweakHash) ChainTweak(epoch uint32, chainIndex uint8, posInChain uint8) th.Tweak {
	// Pack as: (epoch << 24) | (chainIndex << 16) | (posInChain << 8) | separator
	tweak := make([]byte, 8)
	val := uint64(epoch)<<24 | uint64(chainIndex)<<16 | uint64(posInChain)<<8 | TweakSeparatorChainHash
	binary.LittleEndian.PutUint64(tweak, val)
	return tweak
}

// MessageTweak creates a message tweak for given epoch
func (p *PoseidonTweakHash) MessageTweak(epoch uint32) th.Tweak {
	tweak := make([]byte, 5)
	tweak[0] = TweakSeparatorMessageHash
	binary.LittleEndian.PutUint32(tweak[1:], epoch)
	return tweak
}

// OutputLen returns the output length in bytes
func (p *PoseidonTweakHash) OutputLen() int {
	return p.hashLen * 4 // 4 bytes per field element
}

// ParameterLen returns the parameter length in bytes
func (p *PoseidonTweakHash) ParameterLen() int {
	return p.parameterLen * 4 // 4 bytes per field element
}

// RandDomain generates a random domain element (for testing)
func (p *PoseidonTweakHash) RandDomain(rng io.Reader) th.Domain {
	domain := make([]byte, p.OutputLen())
	if _, err := io.ReadFull(rng, domain); err != nil {
		panic("failed to generate random domain")
	}
	return domain
}

// tweakToFieldElements converts tweak bytes to field elements
func (p *PoseidonTweakHash) tweakToFieldElements(tweak th.Tweak) []babybear.Element {
	// Convert tweak to a big integer, then decompose in base p
	// This matches the Rust implementation's approach
	
	// First byte is separator
	separator := tweak[0]
	
	var acc uint64
	switch separator {
	case TweakSeparatorTreeHash:
		// Tree tweak: level and position
		acc = binary.LittleEndian.Uint64(tweak)
	case TweakSeparatorChainHash:
		// Chain tweak: epoch, chain index, position
		acc = binary.LittleEndian.Uint64(tweak)
	case TweakSeparatorMessageHash:
		// Message tweak: epoch
		if len(tweak) >= 5 {
			epoch := binary.LittleEndian.Uint32(tweak[1:])
			acc = uint64(epoch)<<8 | TweakSeparatorMessageHash
		}
	}
	
	// Decompose in base p (BabyBear prime)
	result := make([]babybear.Element, p.tweakLen)
	for i := 0; i < p.tweakLen; i++ {
		var e babybear.Element
		e.SetUint64(acc % P)
		result[i] = e
		acc /= P
	}
	
	return result
}

// computeCapacityValue computes the capacity for sponge construction
func (p *PoseidonTweakHash) computeCapacityValue(params []babybear.Element, tweak []babybear.Element) []babybear.Element {
	// Combine params and tweak for domain separation
	capacity := make([]babybear.Element, 0, len(params)+len(tweak))
	capacity = append(capacity, params...)
	capacity = append(capacity, tweak...)
	return capacity
}

// poseidonSponge applies the sponge construction
func (p *PoseidonTweakHash) poseidonSponge(capacity []babybear.Element, input []babybear.Element) []babybear.Element {
	perm := poseidon.NewPoseidon2_24()
	width := 24
	rate := width - len(capacity)
	
	// Initialize state
	state := make([]babybear.Element, width)
	copy(state[rate:], capacity)
	
	// Absorb phase
	for i := 0; i < len(input); i += rate {
		end := i + rate
		if end > len(input) {
			end = len(input)
		}
		
		// Add input to state
		for j := 0; j < end-i; j++ {
			var sum babybear.Element
			sum.Add(&state[j], &input[i+j])
			state[j] = sum
		}
		
		// Apply permutation
		perm.Permute(state)
	}
	
	// Squeeze phase - extract hashLen elements
	output := make([]babybear.Element, p.hashLen)
	copy(output, state[:p.hashLen])
	
	return output
}

// bytesToFieldElements converts bytes to field elements
func bytesToFieldElements(data []byte, numElements int) []babybear.Element {
	result := make([]babybear.Element, numElements)
	for i := 0; i < numElements; i++ {
		offset := i * 4
		if offset+4 <= len(data) {
			var e babybear.Element
			e.SetBytes(data[offset : offset+4])
			result[i] = e
		} else if offset < len(data) {
			// Partial element
			partial := make([]byte, 4)
			copy(partial, data[offset:])
			var e babybear.Element
			e.SetBytes(partial)
			result[i] = e
		}
	}
	return result
}

// fieldElementsToBytes converts field elements to bytes
func fieldElementsToBytes(elements []babybear.Element) []byte {
	result := make([]byte, 0, len(elements)*4)
	for _, elem := range elements {
		b := elem.Bytes()
		result = append(result, b[:]...)
	}
	return result
}