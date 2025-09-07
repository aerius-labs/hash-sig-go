package tweak

import (
	"encoding/binary"
	
	"github.com/aerius-labs/hash-sig-go/th"
)

// ChainTweak creates a tweak for hash chain operations
// Implements Eq. (17) from the paper: tweak(ep,i,k)
func ChainTweak(epoch uint32, chainIndex uint8, posInChain uint8) th.Tweak {
	// Format: separator || epoch (4 bytes BE) || chainIndex (1 byte) || posInChain (1 byte)
	tweak := make([]byte, 0, 7)
	tweak = append(tweak, th.TweakSeparatorChainHash)
	tweak = binary.BigEndian.AppendUint32(tweak, epoch)
	tweak = append(tweak, chainIndex)
	tweak = append(tweak, posInChain)
	return tweak
}

// TreeTweak creates a tweak for Merkle tree operations  
// Implements Eq. (18) from the paper: tweakmt(l,i)
func TreeTweak(level uint8, posInLevel uint32) th.Tweak {
	// Format: separator || level (1 byte) || posInLevel (4 bytes BE)
	tweak := make([]byte, 0, 6)
	tweak = append(tweak, th.TweakSeparatorTreeHash)
	tweak = append(tweak, level)
	tweak = binary.BigEndian.AppendUint32(tweak, posInLevel)
	return tweak
}

// MessageTweak creates a tweak for message hashing
// Implements Eq. (19) from the paper: tweakm(ep)
// NOTE: Uses little-endian for epoch to match Rust implementation
func MessageTweak(epoch uint32) th.Tweak {
	// Format: separator || epoch (4 bytes LE)
	tweak := make([]byte, 0, 5)
	tweak = append(tweak, th.TweakSeparatorMessageHash)
	tweak = binary.LittleEndian.AppendUint32(tweak, epoch)
	return tweak
}