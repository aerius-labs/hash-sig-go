package message_hash

import (
	"crypto/rand"
	"fmt"
	"reflect"
	"testing"
)

// Test message hash functionality
func TestSHA3MessageHash(t *testing.T) {
	// Test configuration matching Rust's ShaMessageHash192x3
	mh := NewSHA3MessageHash(24, 24, 48, 4)
	
	// Fixed test inputs
	param := make([]byte, 24)
	for i := range param {
		param[i] = byte(i)
	}
	
	randomness := make([]byte, 24)
	for i := range randomness {
		randomness[i] = byte(255 - i)
	}
	
	message := make([]byte, 32)
	for i := range message {
		message[i] = byte(i * 7)
	}
	
	epoch := uint32(42)
	
	// Apply message hash
	chunks := mh.Apply(param, epoch, randomness, message)
	
	// Verify output
	if len(chunks) != 48 {
		t.Fatalf("Expected 48 chunks, got %d", len(chunks))
	}
	
	// Each chunk should be 4 bits (0-15)
	for i, chunk := range chunks {
		if chunk > 15 {
			t.Fatalf("Chunk %d out of range: %d > 15", i, chunk)
		}
	}
	
	// Test determinism
	chunks2 := mh.Apply(param, epoch, randomness, message)
	if !reflect.DeepEqual(chunks, chunks2) {
		t.Fatal("Message hash is not deterministic")
	}
}

// Test different chunk sizes
func TestSHA3MessageHashChunkSizes(t *testing.T) {
	testCases := []struct {
		chunkSize int
		dimension int
		maxValue  uint8
	}{
		{1, 256, 1},  // 256 1-bit chunks
		{2, 128, 3},  // 128 2-bit chunks
		{4, 64, 15},  // 64 4-bit chunks
		{8, 32, 255}, // 32 8-bit chunks
	}
	
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ChunkSize%d", tc.chunkSize), func(t *testing.T) {
			mh := NewSHA3MessageHash(24, 24, tc.dimension, tc.chunkSize)
			
			param := make([]byte, 24)
			rand.Read(param)
			
			randomness := mh.RandRandomness(rand.Reader)
			message := make([]byte, 32)
			rand.Read(message)
			
			chunks := mh.Apply(param, 0, randomness, message)
			
			if len(chunks) != tc.dimension {
				t.Fatalf("Expected %d chunks, got %d", tc.dimension, len(chunks))
			}
			
			for i, chunk := range chunks {
				if chunk > tc.maxValue {
					t.Fatalf("Chunk %d exceeds max value: %d > %d", i, chunk, tc.maxValue)
				}
			}
		})
	}
}

// Benchmark message hash
func BenchmarkSHA3MessageHash(b *testing.B) {
	mh := NewSHA3MessageHash(24, 24, 48, 4)
	param := make([]byte, 24)
	rand.Read(param)
	randomness := mh.RandRandomness(rand.Reader)
	message := make([]byte, 32)
	rand.Read(message)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mh.Apply(param, 0, randomness, message)
	}
}