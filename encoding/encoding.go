package encoding

import (
	"errors"
	"io"
	
	"github.com/aerius-labs/hash-sig-go/th"
)

// ErrEncodingFailed indicates encoding failed and needs retry with new randomness
var ErrEncodingFailed = errors.New("encoding failed, retry needed")

// Codeword represents an encoded message as chunks
type Codeword []uint8

// IncomparableEncoding defines the interface for incomparable encoding schemes
// These ensure no two distinct codewords are comparable (Definition 13)
type IncomparableEncoding interface {
	// Encode attempts to encode a message into a codeword
	// Returns ErrEncodingFailed if encoding fails (needs new randomness)
	Encode(P th.Params, msg []byte, rho []byte, epoch uint32) (Codeword, error)
	
	// RandRandomness generates randomness for encoding
	RandRandomness(rng io.Reader) []byte
	
	// Dimension returns the number of chunks in a codeword (v)
	Dimension() int
	
	// Base returns the base of the encoding (2^w)
	Base() int
	
	// ChunkSize returns w (bits per chunk)
	ChunkSize() int
	
	// MaxTries returns the maximum number of encoding attempts
	MaxTries() int
	
	// NeedsRetry indicates if this encoding may fail and need retries
	// (true for Target-Sum, false for Winternitz)
	NeedsRetry() bool
}