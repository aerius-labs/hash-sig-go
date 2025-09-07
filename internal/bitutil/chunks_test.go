package bitutil

import (
	"bytes"
	"crypto/rand"
	"reflect"
	"testing"
)

// Test specific byte-to-chunks conversion matching Rust implementation
func TestBytesToChunksSpecific(t *testing.T) {
	// Test case from Rust: 0b0110_1100, 0b1010_0110
	byteA := byte(0b01101100)
	byteB := byte(0b10100110)
	
	input := []byte{byteA, byteB}
	
	// Test 2-bit chunks
	// Expected: [0b00, 0b11, 0b10, 0b01, 0b10, 0b01, 0b10, 0b10]
	expected2 := []uint8{0b00, 0b11, 0b10, 0b01, 0b10, 0b01, 0b10, 0b10}
	
	chunks2, err := BytesToChunks(input, 2)
	if err != nil {
		t.Fatalf("BytesToChunks failed: %v", err)
	}
	
	if !reflect.DeepEqual(chunks2, expected2) {
		t.Fatalf("2-bit chunks mismatch\nGot:      %v\nExpected: %v", chunks2, expected2)
	}
	
	// Test 8-bit chunks (should return original bytes)
	chunks8, err := BytesToChunks(input, 8)
	if err != nil {
		t.Fatalf("BytesToChunks failed: %v", err)
	}
	
	if !bytes.Equal(chunks8, input) {
		t.Fatalf("8-bit chunks should return original bytes\nGot:      %v\nExpected: %v", chunks8, input)
	}
}

// Test all chunk sizes with manual verification
func TestBytesToChunksAllSizes(t *testing.T) {
	testByte := byte(0b11010010) // Binary: 1101 0010
	
	testCases := []struct {
		chunkSize int
		expected  []uint8
	}{
		{
			chunkSize: 1,
			// Bits from LSB to MSB: 0,1,0,0,1,0,1,1
			expected: []uint8{0, 1, 0, 0, 1, 0, 1, 1},
		},
		{
			chunkSize: 2,
			// 2-bit chunks from LSB: 10, 00, 01, 11
			expected: []uint8{0b10, 0b00, 0b01, 0b11},
		},
		{
			chunkSize: 4,
			// 4-bit chunks: 0010, 1101
			expected: []uint8{0b0010, 0b1101},
		},
		{
			chunkSize: 8,
			// Full byte
			expected: []uint8{0b11010010},
		},
	}
	
	for _, tc := range testCases {
		chunks, err := BytesToChunks([]byte{testByte}, tc.chunkSize)
		if err != nil {
			t.Fatalf("BytesToChunks failed for size %d: %v", tc.chunkSize, err)
		}
		
		if !reflect.DeepEqual(chunks, tc.expected) {
			t.Errorf("Chunk size %d mismatch\nGot:      %08b\nExpected: %08b",
				tc.chunkSize, chunks, tc.expected)
		}
	}
}

// Property test: chunks should be reversible
func TestBytesToChunksReversible(t *testing.T) {
	for chunkSize := range []int{1, 2, 4, 8} {
		actualSize := []int{1, 2, 4, 8}[chunkSize]
		
		// Generate random bytes
		original := make([]byte, 32)
		rand.Read(original)
		
		// Convert to chunks
		chunks, err := BytesToChunks(original, actualSize)
		if err != nil {
			t.Fatalf("BytesToChunks failed: %v", err)
		}
		
		// Reconstruct bytes from chunks
		reconstructed := make([]byte, len(original))
		chunksPerByte := 8 / actualSize
		
		for i := 0; i < len(original); i++ {
			var b byte
			for j := 0; j < chunksPerByte; j++ {
				chunkIdx := i*chunksPerByte + j
				b |= chunks[chunkIdx] << (j * actualSize)
			}
			reconstructed[i] = b
		}
		
		if !bytes.Equal(original, reconstructed) {
			t.Errorf("Chunks not reversible for size %d", actualSize)
		}
	}
}

// Test TruncateBits function
func TestTruncateBits(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		numBits  int
		expected []byte
	}{
		{
			name:     "Exact byte boundary",
			input:    []byte{0xFF, 0xFF, 0xFF},
			numBits:  16,
			expected: []byte{0xFF, 0xFF},
		},
		{
			name:     "Non-byte boundary",
			input:    []byte{0xFF, 0xFF},
			numBits:  12,
			expected: []byte{0xFF, 0x0F},
		},
		{
			name:     "Single bit",
			input:    []byte{0xFF},
			numBits:  1,
			expected: []byte{0x01},
		},
		{
			name:     "Zero bits",
			input:    []byte{0xFF, 0xFF},
			numBits:  0,
			expected: []byte{},
		},
		{
			name:     "More bits than available",
			input:    []byte{0xAB},
			numBits:  16,
			expected: []byte{0xAB},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := TruncateBits(tc.input, tc.numBits)
			if !bytes.Equal(result, tc.expected) {
				t.Errorf("TruncateBits failed\nInput:    %x\nBits:     %d\nGot:      %x\nExpected: %x",
					tc.input, tc.numBits, result, tc.expected)
			}
		})
	}
}

// Test ExtractWBitChunks function
func TestExtractWBitChunks(t *testing.T) {
	// Test data: 0xFF, 0x00, 0xAA = 11111111, 00000000, 10101010
	data := []byte{0xFF, 0x00, 0xAA}
	
	testCases := []struct {
		w         int
		numChunks int
		expected  []uint32
	}{
		{
			w:         4,
			numChunks: 6,
			expected:  []uint32{0xF, 0xF, 0x0, 0x0, 0xA, 0xA},
		},
		{
			w:         8,
			numChunks: 3,
			expected:  []uint32{0xFF, 0x00, 0xAA},
		},
		{
			w:         2,
			numChunks: 8,
			expected:  []uint32{0x3, 0x3, 0x3, 0x3, 0x0, 0x0, 0x0, 0x0},
		},
	}
	
	for _, tc := range testCases {
		chunks, err := ExtractWBitChunks(data, tc.w, tc.numChunks)
		if err != nil {
			t.Fatalf("ExtractWBitChunks failed: %v", err)
		}
		
		if !reflect.DeepEqual(chunks, tc.expected) {
			t.Errorf("ExtractWBitChunks mismatch for w=%d\nGot:      %v\nExpected: %v",
				tc.w, chunks, tc.expected)
		}
	}
}

// Benchmark BytesToChunks
func BenchmarkBytesToChunks(b *testing.B) {
	data := make([]byte, 256)
	rand.Read(data)
	
	b.Run("ChunkSize1", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			BytesToChunks(data, 1)
		}
	})
	
	b.Run("ChunkSize2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			BytesToChunks(data, 2)
		}
	})
	
	b.Run("ChunkSize4", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			BytesToChunks(data, 4)
		}
	})
	
	b.Run("ChunkSize8", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			BytesToChunks(data, 8)
		}
	})
}