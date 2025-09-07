package message_hash

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
	
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/aerius-labs/hash-sig-go/th"
)

// Test basic Poseidon message hash functionality
func TestPoseidonMessageHashApply(t *testing.T) {
	// Test configuration matching Rust's PoseidonMessageHash445
	mh := NewPoseidonMessageHash(
		4, // parameterLen
		4, // randLen
		5, // msgHashLenFE
		32, // numChunks
		16, // base
		2, // tweakLenFE
		9, // msgLenFE
	)
	
	// Generate random inputs
	params := make(th.Params, 16) // 4 field elements * 4 bytes
	rand.Read(params)
	
	message := make([]byte, 32)
	rand.Read(message)
	
	randomness := make([]byte, 16) // 4 field elements * 4 bytes
	rand.Read(randomness)
	
	epoch := uint32(13)
	
	// Hash the message
	result := mh.Hash(params, message, randomness, epoch)
	
	// Verify output length
	expectedLen := mh.OutputLen()
	if len(result) != expectedLen {
		t.Errorf("Expected output length %d, got %d", expectedLen, len(result))
	}
	
	// Test consistency - same inputs should give same output
	result2 := mh.Hash(params, message, randomness, epoch)
	if !bytes.Equal(result, result2) {
		t.Error("Same inputs produced different results")
	}
	
	// Different epoch should give different result
	result3 := mh.Hash(params, message, randomness, epoch+1)
	if bytes.Equal(result, result3) {
		t.Error("Different epochs produced same result")
	}
}

// Test epoch encoding
func TestEncodeEpoch(t *testing.T) {
	mh := NewPoseidonMessageHash(4, 4, 5, 32, 16, 2, 9)
	
	testCases := []struct {
		name  string
		epoch uint32
	}{
		{"Zero", 0},
		{"Small", 42},
		{"Medium", 0x1234},
		{"Large", 0x12345678},
		{"Max", 0xFFFFFFFF},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Compute expected encoding
			sep := uint64(0x02) // MESSAGE_HASH separator
			epochBigint := new(big.Int).SetUint64(uint64(tc.epoch)<<8 | sep)
			
			// Convert to field elements (2 elements for tweakLenFE=2)
			p := new(big.Int).SetUint64(2013265921)
			expected := make([]babybear.Element, 2)
			
			remainder := new(big.Int).Set(epochBigint)
			for i := 0; i < 2; i++ {
				var e babybear.Element
				digit := new(big.Int).Mod(remainder, p)
				e.SetBigInt(digit)
				expected[i] = e
				remainder.Div(remainder, p)
			}
			
			// Get actual encoding
			actual := mh.epochToFieldElements(tc.epoch)
			
			// Compare
			for i := 0; i < len(expected); i++ {
				if !actual[i].Equal(&expected[i]) {
					t.Errorf("Epoch encoding mismatch at index %d for epoch %d", i, tc.epoch)
				}
			}
		})
	}
}

// Test epoch encoding injectivity
func TestEpochEncodingInjective(t *testing.T) {
	mh := NewPoseidonMessageHash(4, 4, 5, 32, 16, 2, 9)
	
	seen := make(map[string]struct{})
	
	// Test many random epochs
	for i := 0; i < 10000; i++ {
		b := make([]byte, 4)
		rand.Read(b)
		epoch := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		
		fields := mh.epochToFieldElements(epoch)
		
		// Convert to string for map key
		key := ""
		for _, f := range fields {
			key += f.String() + ","
		}
		
		if _, exists := seen[key]; exists {
			// Check if it's actually the same epoch (ok) or a collision (bad)
			if key != "" { // Only fail on actual collision
				t.Fatalf("Collision found: epoch %d and previous epoch have same encoding", epoch)
			}
		}
		seen[key] = struct{}{}
	}
}

// Test message encoding
func TestEncodeMessage(t *testing.T) {
	testCases := []struct {
		name    string
		message []byte
	}{
		{"AllZeros", make([]byte, 32)},
		{"AllOnes", bytes.Repeat([]byte{0xFF}, 32)},
		{"Alternating", func() []byte {
			msg := make([]byte, 32)
			for i := range msg {
				if i%2 == 0 {
					msg[i] = 0x00
				} else {
					msg[i] = 0xFF
				}
			}
			return msg
		}()},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Convert message to field elements
			fields := bytesToFieldElements(tc.message, 9) // 9 field elements for 32 bytes
			
			// Verify we got the right number of field elements
			if len(fields) != 9 {
				t.Errorf("Expected 9 field elements, got %d", len(fields))
			}
			
			// Convert back and check if we can recover (approximately) the original
			recovered := fieldElementsToBytes(fields)
			
			// We should have at least 32 bytes
			if len(recovered) < 32 {
				t.Errorf("Recovered message too short: %d bytes", len(recovered))
			}
			
			// First 32 bytes should match
			if !bytes.Equal(tc.message, recovered[:32]) {
				t.Error("Message encoding/decoding mismatch")
			}
		})
	}
}

// Test randomness generation
func TestRandNotAllSame(t *testing.T) {
	mh := NewPoseidonMessageHash(4, 4, 5, 32, 16, 2, 9)
	
	allSameCount := 0
	trials := 10
	
	for i := 0; i < trials; i++ {
		randBytes := make([]byte, mh.RandLen())
		rand.Read(randBytes)
		
		// Check if all bytes are identical
		if len(randBytes) > 0 {
			first := randBytes[0]
			allSame := true
			for _, b := range randBytes[1:] {
				if b != first {
					allSame = false
					break
				}
			}
			if allSame {
				allSameCount++
			}
		}
	}
	
	if allSameCount == trials {
		t.Error("All random values had identical bytes")
	}
}

// Test w=1 configuration (matching Rust's PoseidonMessageHashW1)
func TestPoseidonMessageHashW1(t *testing.T) {
	// Configuration for w=1
	mh := NewPoseidonMessageHash(
		5, // parameterLen
		5, // randLen
		5, // msgHashLenFE
		155, // numChunks for w=1
		2, // base for w=1
		2, // tweakLenFE
		9, // msgLenFE
	)
	
	// Generate random inputs
	params := make(th.Params, 20) // 5 field elements * 4 bytes
	rand.Read(params)
	
	message := make([]byte, 32)
	rand.Read(message)
	
	randomness := make([]byte, 20) // 5 field elements * 4 bytes
	rand.Read(randomness)
	
	epoch := uint32(13)
	
	// Hash the message
	result := mh.Hash(params, message, randomness, epoch)
	
	// Verify output length
	expectedLen := mh.OutputLen()
	if len(result) != expectedLen {
		t.Errorf("Expected output length %d, got %d", expectedLen, len(result))
	}
	
	// Should produce 155 chunks for w=1
	// This would be verified when decoding for actual encoding use
}