package bitutil

import "errors"

// BytesToChunks splits bytes into w-bit chunks
// Similar to bytes_to_chunks in the Rust implementation
func BytesToChunks(bytes []byte, chunkSize int) ([]uint8, error) {
	// Only chunk sizes 1, 2, 4, or 8 are valid
	if chunkSize != 1 && chunkSize != 2 && chunkSize != 4 && chunkSize != 8 {
		return nil, errors.New("chunk size must be 1, 2, 4, or 8")
	}
	
	chunksPerByte := 8 / chunkSize
	out := make([]uint8, 0, len(bytes)*chunksPerByte)
	
	switch chunkSize {
	case 8:
		// Copy as-is
		out = append(out, bytes...)
	case 4:
		// Low nibble, then high nibble
		for _, b := range bytes {
			out = append(out, b&0x0F)
			out = append(out, b>>4)
		}
	case 2:
		// 4 two-bit chunks: bits [1:0], [3:2], [5:4], [7:6]
		for _, b := range bytes {
			out = append(out, b&0x03)
			out = append(out, (b>>2)&0x03)
			out = append(out, (b>>4)&0x03)
			out = append(out, (b>>6)&0x03)
		}
	case 1:
		// 8 one-bit chunks
		for _, b := range bytes {
			for i := 0; i < 8; i++ {
				out = append(out, (b>>i)&0x01)
			}
		}
	}
	
	return out, nil
}

// TruncateBits truncates data to exactly numBits bits
// Returns a new slice with the truncated data
func TruncateBits(data []byte, numBits int) []byte {
	if numBits <= 0 {
		return []byte{}
	}
	
	numBytes := (numBits + 7) / 8
	if numBytes > len(data) {
		numBytes = len(data)
	}
	
	result := make([]byte, numBytes)
	copy(result, data[:numBytes])
	
	// Clear unused bits in the last byte if necessary
	remainingBits := numBits % 8
	if remainingBits > 0 && numBytes > 0 {
		mask := byte((1 << remainingBits) - 1)
		result[numBytes-1] &= mask
	}
	
	return result
}

// ExtractWBitChunks extracts w-bit chunks from data starting at bit offset
// Returns exactly numChunks chunks
func ExtractWBitChunks(data []byte, w int, numChunks int) ([]uint32, error) {
	if w <= 0 || w > 32 {
		return nil, errors.New("w must be between 1 and 32")
	}
	
	totalBits := len(data) * 8
	requiredBits := w * numChunks
	if totalBits < requiredBits {
		return nil, errors.New("insufficient data for requested chunks")
	}
	
	chunks := make([]uint32, numChunks)
	bitPos := 0
	
	for i := 0; i < numChunks; i++ {
		chunk := uint32(0)
		for j := 0; j < w; j++ {
			byteIdx := bitPos / 8
			bitIdx := bitPos % 8
			if byteIdx < len(data) {
				bit := (data[byteIdx] >> bitIdx) & 1
				chunk |= uint32(bit) << j
			}
			bitPos++
		}
		chunks[i] = chunk
	}
	
	return chunks, nil
}