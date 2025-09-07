package message_hash

import (
	"crypto/rand"
	"testing"
	
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/aerius-labs/hash-sig-go/th"
)

// Test top-level Poseidon message hash
func TestTopLevelPoseidonApply(t *testing.T) {
	// Configuration matching Rust test
	const (
		BASE         = 12
		DIMENSION    = 40
		FINAL_LAYER  = 175
	)
	
	mh := NewTopLevelPoseidonMessageHash(
		8,  // posOutputLenPerInvFE
		6,  // posInvocations
		48, // posOutputLenFE
		DIMENSION,
		BASE,
		FINAL_LAYER,
		3, // tweakLenFE
		9, // msgLenFE
		4, // parameterLen
		4, // randLen
	)
	
	// Generate random inputs
	params := make(th.Params, 16) // 4 field elements * 4 bytes
	rand.Read(params)
	
	message := make([]byte, 32)
	rand.Read(message)
	
	randomness := make([]byte, 16) // 4 field elements * 4 bytes
	rand.Read(randomness)
	
	epoch := uint32(42)
	
	// Hash the message
	result := mh.Hash(params, message, randomness, epoch)
	
	// Verify output length equals dimension
	if len(result) != DIMENSION {
		t.Errorf("Expected output length %d, got %d", DIMENSION, len(result))
	}
	
	// Verify result is in valid range for base
	for i, val := range result {
		if int(val) >= BASE {
			t.Errorf("Output[%d] = %d exceeds base %d", i, val, BASE)
		}
	}
	
	// Test consistency
	result2 := mh.Hash(params, message, randomness, epoch)
	for i := range result {
		if result[i] != result2[i] {
			t.Error("Same inputs produced different results")
			break
		}
	}
}

// Test map into hypercube part
func TestMapIntoHypercubePart(t *testing.T) {
	const (
		BASE        = 4
		DIMENSION   = 8
		FINAL_LAYER = 10
	)
	
	mh := NewTopLevelPoseidonMessageHash(
		2, 2, 4, // Smaller for testing
		DIMENSION,
		BASE,
		FINAL_LAYER,
		2, 9, 4, 4,
	)
	
	// Test that mapping produces valid vertices
	for trial := 0; trial < 100; trial++ {
		// Generate random field elements
		fieldElems := make([]babybear.Element, 4)
		for i := range fieldElems {
			var e babybear.Element
			b := make([]byte, 4)
			rand.Read(b)
			val := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
			e.SetUint64(uint64(val % 1000000))
			fieldElems[i] = e
		}
		
		vertex := mh.mapIntoHypercubePart(fieldElems)
		
		// Check vertex is valid
		if len(vertex) != DIMENSION {
			t.Errorf("Vertex has wrong dimension: %d", len(vertex))
		}
		
		// Each coordinate should be < BASE
		for i, coord := range vertex {
			if int(coord) >= BASE {
				t.Errorf("Vertex[%d] = %d >= base %d", i, coord, BASE)
			}
		}
		
		// Check sum is within expected range for layers 0..FINAL_LAYER
		sum := 0
		for _, coord := range vertex {
			sum += int(coord)
		}
		
		maxSum := (BASE - 1) * DIMENSION
		if sum > maxSum {
			t.Errorf("Vertex sum %d exceeds max %d", sum, maxSum)
		}
	}
}

// Test property-based testing with various epochs and messages
func TestTopLevelPoseidonProperties(t *testing.T) {
	const (
		BASE        = 12
		DIMENSION   = 40
		FINAL_LAYER = 175
	)
	
	mh := NewTopLevelPoseidonMessageHash(
		8, 6, 48,
		DIMENSION,
		BASE,
		FINAL_LAYER,
		3, 9, 4, 4,
	)
	
	params := make(th.Params, 16)
	rand.Read(params)
	
	randomness := make([]byte, 16)
	rand.Read(randomness)
	
	// Test with different epochs
	for epoch := uint32(0); epoch < 1000; epoch += 100 {
		message := make([]byte, 32)
		rand.Read(message)
		
		result := mh.Hash(params, message, randomness, epoch)
		
		// Verify basic properties
		if len(result) != DIMENSION {
			t.Fatalf("Wrong output dimension for epoch %d", epoch)
		}
		
		// Check all values are in range
		for i, val := range result {
			if int(val) >= BASE {
				t.Errorf("Invalid value at epoch %d, index %d: %d", epoch, i, val)
			}
		}
	}
}