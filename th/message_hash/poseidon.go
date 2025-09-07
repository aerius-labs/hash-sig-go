package message_hash

import (
	"math/big"
	
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/aerius-labs/hash-sig-go/poseidon"
	"github.com/aerius-labs/hash-sig-go/th"
)

// PoseidonMessageHash implements message hashing using Poseidon
type PoseidonMessageHash struct {
	parameterLen int
	randLen      int
	msgHashLenFE int // Message hash length in field elements
	numChunks    int
	base         int
	tweakLenFE   int
	msgLenFE     int // Message length in field elements
}

// NewPoseidonMessageHash creates a new Poseidon message hash
func NewPoseidonMessageHash(
	parameterLen, randLen, msgHashLenFE, numChunks, base, tweakLenFE, msgLenFE int,
) *PoseidonMessageHash {
	return &PoseidonMessageHash{
		parameterLen: parameterLen,
		randLen:      randLen,
		msgHashLenFE: msgHashLenFE,
		numChunks:    numChunks,
		base:         base,
		tweakLenFE:   tweakLenFE,
		msgLenFE:     msgLenFE,
	}
}

// Hash hashes a message with parameters, randomness, and epoch
func (h *PoseidonMessageHash) Hash(params th.Params, msg []byte, rand []byte, epoch uint32) []byte {
	// Convert message to field elements (32 bytes -> 8 field elements of 4 bytes each)
	msgFields := bytesToFieldElements(msg, h.msgLenFE)
	
	// Convert randomness to field elements
	randFields := bytesToFieldElements(rand, h.randLen)
	
	// Convert parameters to field elements
	paramFields := bytesToFieldElements(params, h.parameterLen)
	
	// Create epoch tweak as field elements
	epochFields := h.epochToFieldElements(epoch)
	
	// Compute capacity value for sponge
	capacity := make([]babybear.Element, 0)
	capacity = append(capacity, paramFields...)
	capacity = append(capacity, epochFields...)
	
	// Input is randomness || message
	input := make([]babybear.Element, 0)
	input = append(input, randFields...)
	input = append(input, msgFields...)
	
	// Apply Poseidon sponge
	result := h.poseidonSponge(capacity, input)
	
	// Decode field elements to chunks
	return h.decodeToChunks(result[:h.msgHashLenFE])
}

// OutputLen returns the output length in bytes (number of chunks)
func (h *PoseidonMessageHash) OutputLen() int {
	return h.numChunks
}

// RandLen returns the randomness length in bytes
func (h *PoseidonMessageHash) RandLen() int {
	return h.randLen * 4
}

// Dimension returns the number of chunks
func (h *PoseidonMessageHash) Dimension() int {
	return h.numChunks
}

// Base returns the base value
func (h *PoseidonMessageHash) Base() int {
	return h.base
}

// ChunkSize returns the chunk size in bits
func (h *PoseidonMessageHash) ChunkSize() int {
	// Calculate chunk size in bits from base
	// base = 2^chunkSize, so chunkSize = log2(base)
	chunkSize := 0
	base := h.base
	for base > 1 {
		base >>= 1
		chunkSize++
	}
	return chunkSize
}

// epochToFieldElements converts epoch to field elements with message hash separator
func (h *PoseidonMessageHash) epochToFieldElements(epoch uint32) []babybear.Element {
	// Pack as: (epoch << 8) | separator
	val := uint64(epoch)<<8 | 0x02 // MESSAGE_HASH separator
	
	// Decompose in base p
	result := make([]babybear.Element, h.tweakLenFE)
	for i := 0; i < h.tweakLenFE; i++ {
		var e babybear.Element
		e.SetUint64(val % 2013265921)
		result[i] = e
		val /= 2013265921
	}
	
	return result
}

// poseidonSponge applies the sponge construction
func (h *PoseidonMessageHash) poseidonSponge(capacity []babybear.Element, input []babybear.Element) []babybear.Element {
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
	
	// Squeeze phase
	output := make([]babybear.Element, h.msgHashLenFE)
	copy(output, state[:h.msgHashLenFE])
	
	return output
}

// bytesToFieldElements converts bytes to field elements using base-p decomposition
func bytesToFieldElements(data []byte, numElements int) []babybear.Element {
	// Interpret data as a little-endian integer
	acc := new(big.Int).SetBytes(reverseBytes(data))
	
	// Perform base-p decomposition
	p := big.NewInt(2013265921) // BabyBear prime
	result := make([]babybear.Element, numElements)
	
	for i := 0; i < numElements; i++ {
		digit := new(big.Int).Mod(acc, p)
		var e babybear.Element
		e.SetBigInt(digit)
		result[i] = e
		acc.Div(acc, p)
	}
	
	return result
}

// fieldElementsToBytes converts field elements back to bytes
func fieldElementsToBytes(elements []babybear.Element) []byte {
	// Reconstruct the big integer from base-p digits
	acc := new(big.Int)
	p := big.NewInt(2013265921)
	
	// Process in reverse order to reconstruct correctly
	for i := len(elements) - 1; i >= 0; i-- {
		digit := elements[i].BigInt(new(big.Int))
		acc.Mul(acc, p)
		acc.Add(acc, digit)
	}
	
	// Convert to bytes (big-endian) then reverse for little-endian
	bytes := acc.Bytes()
	
	// Calculate expected byte length based on field elements
	// Each field element can store roughly 31 bits, so we estimate
	expectedLen := (len(elements) * 31) / 8
	if expectedLen < 32 {
		expectedLen = 32 // Minimum 32 bytes for message
	}
	
	// Pad with zeros if needed
	if len(bytes) < expectedLen {
		padded := make([]byte, expectedLen)
		copy(padded[expectedLen-len(bytes):], bytes)
		bytes = padded
	}
	
	return reverseBytes(bytes)
}

// reverseBytes reverses a byte slice
func reverseBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := range b {
		result[i] = b[len(b)-1-i]
	}
	return result
}

// decodeToChunks decodes field elements to chunks in base-BASE
func (h *PoseidonMessageHash) decodeToChunks(fieldElements []babybear.Element) []byte {
	// Combine field elements into one big integer
	acc := new(big.Int)
	p := big.NewInt(2013265921) // BabyBear prime
	
	for _, fe := range fieldElements {
		feBig := fe.BigInt(new(big.Int))
		acc.Mul(acc, p)
		acc.Add(acc, feBig)
	}
	
	// Convert to base-BASE chunks
	base := big.NewInt(int64(h.base))
	chunks := make([]byte, h.numChunks)
	
	for i := 0; i < h.numChunks; i++ {
		chunk := new(big.Int).Mod(acc, base)
		chunks[i] = byte(chunk.Int64())
		acc.Div(acc, base)
	}
	
	return chunks
}

