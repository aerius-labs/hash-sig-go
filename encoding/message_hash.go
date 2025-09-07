package encoding

import "github.com/aerius-labs/hash-sig-go/th"

// MessageHash defines the interface for message hash functions
type MessageHash interface {
	// Hash applies the message hash function
	Hash(params th.Params, msg []byte, rand []byte, epoch uint32) []byte
	
	// OutputLen returns the output length in bytes
	OutputLen() int
	
	// RandLen returns the randomness length in bytes  
	RandLen() int
	
	// Dimension returns the number of chunks
	Dimension() int
	
	// Base returns the base value (2^w for Winternitz)
	Base() int
	
	// ChunkSize returns the chunk size in bits (w)
	ChunkSize() int
}