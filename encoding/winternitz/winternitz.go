package winternitz

import (
	"encoding/binary"
	"io"
	"math"
	
	"github.com/aerius-labs/hash-sig-go/encoding"
	"github.com/aerius-labs/hash-sig-go/internal/bitutil"
	"github.com/aerius-labs/hash-sig-go/th"
)

// WinternitzEncoding implements the basic Winternitz OTS encoding (Construction 5)
type WinternitzEncoding struct {
	messageHash         encoding.MessageHash
	chunkSize          int  // w in bits
	numChunksChecksum  int  // n₁
	numChunksMessage   int  // n₀
}

// NewWinternitzEncoding creates a new Winternitz encoding
// numChunksChecksum must be precomputed as:
// n₁ = ⌊log_{2^w}(n₀(2^w−1))⌋ + 1
func NewWinternitzEncoding(messageHash encoding.MessageHash, chunkSize int, numChunksChecksum int) *WinternitzEncoding {
	if chunkSize != 1 && chunkSize != 2 && chunkSize != 4 && chunkSize != 8 {
		panic("chunk size must be 1, 2, 4, or 8")
	}
	
	// Verify consistency
	if messageHash.ChunkSize() != chunkSize {
		panic("message hash chunk size must match encoding chunk size")
	}
	
	// Verify checksum length is correct
	base := 1 << chunkSize
	numChunksMessage := messageHash.Dimension()
	maxChecksum := numChunksMessage * (base - 1)
	expectedChecksumChunks := int(math.Floor(math.Log(float64(maxChecksum))/math.Log(float64(base)))) + 1
	
	if numChunksChecksum != expectedChecksumChunks {
		panic("incorrect number of checksum chunks")
	}
	
	return &WinternitzEncoding{
		messageHash:        messageHash,
		chunkSize:         chunkSize,
		numChunksChecksum: numChunksChecksum,
		numChunksMessage:  messageHash.Dimension(),
	}
}

// Encode implements the Winternitz encoding
func (w *WinternitzEncoding) Encode(P th.Params, msg []byte, rho []byte, epoch uint32) (encoding.Codeword, error) {
	// Apply message hash to get message chunks
	messageChunks := w.messageHash.Hash(P, msg, rho, epoch)
	
	// Compute checksum
	base := uint64(w.Base())
	checksum := uint64(0)
	for _, chunk := range messageChunks {
		checksum += base - 1 - uint64(chunk)
	}
	
	// Split checksum into chunks (little-endian)
	checksumBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(checksumBytes, checksum)
	
	checksumChunks, err := bitutil.BytesToChunks(checksumBytes, w.chunkSize)
	if err != nil {
		return nil, err
	}
	
	// Build final codeword: message chunks + checksum chunks
	codeword := make(encoding.Codeword, 0, w.Dimension())
	codeword = append(codeword, messageChunks...)
	codeword = append(codeword, checksumChunks[:w.numChunksChecksum]...)
	
	return codeword, nil
}

// RandRandomness generates randomness for encoding
func (w *WinternitzEncoding) RandRandomness(rng io.Reader) []byte {
	// Generate random bytes based on the message hash's randomness length
	randLen := w.messageHash.RandLen()
	rand := make([]byte, randLen)
	rng.Read(rand)
	return rand
}

// Dimension returns v = n₀ + n₁
func (w *WinternitzEncoding) Dimension() int {
	return w.numChunksMessage + w.numChunksChecksum
}

// Base returns 2^w
func (w *WinternitzEncoding) Base() int {
	return 1 << w.chunkSize
}

// ChunkSize returns w
func (w *WinternitzEncoding) ChunkSize() int {
	return w.chunkSize
}

// MaxTries returns 1 (Winternitz always succeeds)
func (w *WinternitzEncoding) MaxTries() int {
	return 1
}

// NeedsRetry returns false (Winternitz always succeeds)
func (w *WinternitzEncoding) NeedsRetry() bool {
	return false
}

// ComputeChecksumLength computes n₁ for given parameters
func ComputeChecksumLength(numChunksMessage int, chunkSize int) int {
	base := 1 << chunkSize
	maxChecksum := numChunksMessage * (base - 1)
	return int(math.Floor(math.Log(float64(maxChecksum))/math.Log(float64(base)))) + 1
}