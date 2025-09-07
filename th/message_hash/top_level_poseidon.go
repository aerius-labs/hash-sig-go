package message_hash

import (
	"math/big"
	
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/aerius-labs/hash-sig-go/hypercube"
	"github.com/aerius-labs/hash-sig-go/poseidon"
	"github.com/aerius-labs/hash-sig-go/th"
)

// TopLevelPoseidonMessageHash maps messages into top layers of a hypercube
type TopLevelPoseidonMessageHash struct {
	posOutputLenPerInvFE int
	posInvocations       int
	posOutputLenFE       int
	dimension            int
	base                 int
	finalLayer           int
	tweakLenFE           int
	msgLenFE             int
	parameterLen         int
	randLen              int
}

// NewTopLevelPoseidonMessageHash creates a new top-level Poseidon message hash
func NewTopLevelPoseidonMessageHash(
	posOutputLenPerInvFE, posInvocations, posOutputLenFE,
	dimension, base, finalLayer,
	tweakLenFE, msgLenFE, parameterLen, randLen int,
) *TopLevelPoseidonMessageHash {
	// Validate constraints
	if posOutputLenFE != posInvocations*posOutputLenPerInvFE {
		panic("POS_OUTPUT_LEN_FE must equal POS_INVOCATIONS * POS_OUTPUT_LEN_PER_INV_FE")
	}
	if posOutputLenPerInvFE > 15 {
		panic("POS_OUTPUT_LEN_PER_INV_FE must be at most 15")
	}
	if posInvocations > 256 {
		panic("POS_INVOCATIONS must be at most 256")
	}
	if base > 256 {
		panic("BASE must be at most 256")
	}
	
	return &TopLevelPoseidonMessageHash{
		posOutputLenPerInvFE: posOutputLenPerInvFE,
		posInvocations:       posInvocations,
		posOutputLenFE:       posOutputLenFE,
		dimension:            dimension,
		base:                 base,
		finalLayer:           finalLayer,
		tweakLenFE:           tweakLenFE,
		msgLenFE:             msgLenFE,
		parameterLen:         parameterLen,
		randLen:              randLen,
	}
}

// Hash hashes a message and maps it into hypercube layers
func (h *TopLevelPoseidonMessageHash) Hash(params th.Params, msg []byte, rand []byte, epoch uint32) []byte {
	// Convert inputs to field elements
	paramFields := bytesToFieldElements(params, h.parameterLen)
	msgFields := bytesToFieldElements(msg, h.msgLenFE)
	randFields := bytesToFieldElements(rand, h.randLen)
	
	// Encode epoch
	epochFields := h.encodeEpoch(epoch)
	
	// Collect all field elements from Poseidon invocations
	allOutputs := make([]babybear.Element, 0, h.posOutputLenFE)
	
	for inv := 0; inv < h.posInvocations; inv++ {
		// Build input for this invocation
		input := make([]babybear.Element, 0)
		
		// Add invocation counter
		var invElem babybear.Element
		invElem.SetUint64(uint64(inv))
		input = append(input, invElem)
		
		// Add parameters
		input = append(input, paramFields...)
		
		// Add epoch encoding
		input = append(input, epochFields...)
		
		// Add randomness
		input = append(input, randFields...)
		
		// Add message
		input = append(input, msgFields...)
		
		// Apply Poseidon compression
		perm := poseidon.NewPoseidon2_24()
		output := h.poseidonCompress(perm, input, h.posOutputLenPerInvFE)
		
		allOutputs = append(allOutputs, output...)
	}
	
	// Map field elements into hypercube
	vertex := h.mapIntoHypercubePart(allOutputs)
	
	return vertex
}

// OutputLen returns the output length (dimension of hypercube vertex)
func (h *TopLevelPoseidonMessageHash) OutputLen() int {
	return h.dimension
}

// RandLen returns the randomness length in bytes
func (h *TopLevelPoseidonMessageHash) RandLen() int {
	return h.randLen * 4
}

// encodeEpoch encodes the epoch as field elements
func (h *TopLevelPoseidonMessageHash) encodeEpoch(epoch uint32) []babybear.Element {
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

// poseidonCompress applies Poseidon compression
func (h *TopLevelPoseidonMessageHash) poseidonCompress(perm *poseidon.Poseidon2, input []babybear.Element, outputLen int) []babybear.Element {
	width := 24
	
	// Pad input to width
	padded := make([]babybear.Element, width)
	copy(padded, input)
	
	// Start with input as initial state
	state := make([]babybear.Element, width)
	copy(state, padded)
	
	// Apply permutation
	perm.Permute(state)
	
	// Feed-forward: add input back
	for i := 0; i < width; i++ {
		var sum babybear.Element
		sum.Add(&state[i], &padded[i])
		state[i] = sum
	}
	
	// Return first outputLen elements
	return state[:outputLen]
}

// mapIntoHypercubePart maps field elements into hypercube vertex
func (h *TopLevelPoseidonMessageHash) mapIntoHypercubePart(fieldElements []babybear.Element) []byte {
	// Combine field elements into one big integer
	acc := new(big.Int)
	base := new(big.Int).SetUint64(2013265921)
	
	for _, fe := range fieldElements {
		acc.Mul(acc, base)
		feBig := fe.BigInt(new(big.Int))
		acc.Add(acc, feBig)
	}
	
	// Get hypercube domain size for layers 0 to finalLayer
	domSize := h.hypercubePartSize()
	acc.Mod(acc, domSize)
	
	// Find which layer and offset within that layer
	layer, offset := h.hypercubeFindLayer(acc)
	
	// Map to vertex coordinates
	return h.mapToVertex(layer, offset)
}

// hypercubePartSize returns the total number of vertices in layers 0 to finalLayer
func (h *TopLevelPoseidonMessageHash) hypercubePartSize() *big.Int {
	info := hypercube.GetLayerInfo(h.base, h.dimension)
	return info.SizesSumInRange(0, h.finalLayer)
}

// hypercubeFindLayer finds which layer contains the vertex at given index
func (h *TopLevelPoseidonMessageHash) hypercubeFindLayer(index *big.Int) (int, *big.Int) {
	info := hypercube.GetLayerInfo(h.base, h.dimension)
	
	cumulative := new(big.Int)
	for layer := 0; layer <= h.finalLayer; layer++ {
		// Use SizesSumInRange to get size of this layer
		layerSize := new(big.Int)
		if layer == 0 {
			layerSize = info.SizesSumInRange(0, 0)
		} else {
			prev := info.SizesSumInRange(0, layer-1)
			curr := info.SizesSumInRange(0, layer)
			layerSize = new(big.Int).Sub(curr, prev)
		}
		
		nextCumulative := new(big.Int).Add(cumulative, layerSize)
		if index.Cmp(nextCumulative) < 0 {
			// Found the layer
			offset := new(big.Int).Sub(index, cumulative)
			return layer, offset
		}
		cumulative = nextCumulative
	}
	
	// Should not reach here if index is valid
	return h.finalLayer, new(big.Int)
}

// mapToVertex maps layer and offset to actual vertex coordinates
func (h *TopLevelPoseidonMessageHash) mapToVertex(layer int, offset *big.Int) []byte {
	// This implements the mapping from (layer, offset) to actual hypercube coordinates
	// For simplicity, using a basic mapping - full implementation would need
	// combinatorial number system decoding
	
	vertex := make([]byte, h.dimension)
	
	if layer == 0 {
		// Layer 0 is all (base-1)s
		for i := range vertex {
			vertex[i] = byte(h.base - 1)
		}
	} else {
		// Distribute the "deficit" from all (base-1)s across coordinates
		// This is a simplified version - full implementation needs proper
		// combinatorial decoding
		
		remaining := offset
		positions := h.dimension
		
		for i := 0; i < h.dimension && positions > 0; i++ {
			// Simplified distribution
			if remaining.Sign() > 0 && positions > 0 {
				val := new(big.Int).Div(remaining, big.NewInt(int64(positions)))
				if val.Cmp(big.NewInt(int64(h.base-1))) > 0 {
					val = big.NewInt(int64(h.base - 1))
				}
				vertex[i] = byte(h.base - 1 - int(val.Int64()))
				remaining.Sub(remaining, val)
				positions--
			} else {
				vertex[i] = byte(h.base - 1)
			}
		}
	}
	
	return vertex
}