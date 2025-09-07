package targetsum

import (
	"fmt"
	"io"
	
	"github.com/aerius-labs/hash-sig-go/encoding"
	"github.com/aerius-labs/hash-sig-go/th"
)

// TargetSumEncoding implements the Target-Sum Winternitz encoding (Construction 6)
type TargetSumEncoding struct {
	messageHash encoding.MessageHash
	targetSum   int  // T - the target sum value
}

// NewTargetSumEncoding creates a new Target-Sum encoding
// targetSum should be close to v*(2^w-1)/2 for best performance
func NewTargetSumEncoding(messageHash encoding.MessageHash, targetSum int) *TargetSumEncoding {
	// Verify target sum is reasonable
	base := messageHash.Base()
	dimension := messageHash.Dimension()
	maxSum := dimension * (base - 1)
	
	if targetSum < 0 || targetSum > maxSum {
		panic(fmt.Sprintf("target sum %d out of range [0, %d]", targetSum, maxSum))
	}
	
	return &TargetSumEncoding{
		messageHash: messageHash,
		targetSum:   targetSum,
	}
}

// Encode implements the Target-Sum encoding
// Returns error if the chunks don't sum to the target (need retry with new ρ)
func (t *TargetSumEncoding) Encode(P th.Params, msg []byte, rho []byte, epoch uint32) (encoding.Codeword, error) {
	// Apply message hash to get chunks
	chunks := t.messageHash.Hash(P, msg, rho, epoch)
	
	// Compute sum
	sum := 0
	for _, chunk := range chunks {
		sum += int(chunk)
	}
	
	// Check if sum equals target
	if sum != t.targetSum {
		return nil, fmt.Errorf("%w: expected sum %d, got %d", encoding.ErrEncodingFailed, t.targetSum, sum)
	}
	
	// Success - return chunks as codeword
	codeword := make(encoding.Codeword, len(chunks))
	for i, chunk := range chunks {
		codeword[i] = chunk
	}
	
	return codeword, nil
}

// RandRandomness generates randomness for encoding
func (t *TargetSumEncoding) RandRandomness(rng io.Reader) []byte {
	// Generate random bytes based on the message hash's randomness length
	randLen := t.messageHash.RandLen()
	rand := make([]byte, randLen)
	rng.Read(rand)
	return rand
}

// Dimension returns v (number of chunks)
func (t *TargetSumEncoding) Dimension() int {
	return t.messageHash.Dimension()
}

// Base returns 2^w
func (t *TargetSumEncoding) Base() int {
	return t.messageHash.Base()
}

// ChunkSize returns w
func (t *TargetSumEncoding) ChunkSize() int {
	return t.messageHash.ChunkSize()
}

// MaxTries returns the maximum number of encoding attempts
func (t *TargetSumEncoding) MaxTries() int {
	// Based on empirical testing in the paper
	return 100000
}

// NeedsRetry returns true (Target-Sum may need retries)
func (t *TargetSumEncoding) NeedsRetry() bool {
	return true
}

// ComputeOptimalTarget computes the optimal target sum T
// delta should be 1.0 or 1.1 as suggested in the paper
func ComputeOptimalTarget(dimension int, chunkSize int, delta float64) int {
	base := 1 << chunkSize
	maxChunkValue := base - 1
	return int(delta * float64(dimension) * float64(maxChunkValue) / 2.0)
}