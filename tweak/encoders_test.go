package tweak

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// Test that tweak encodings are injective (no collisions)
func TestChainTweakInjective(t *testing.T) {
	// Map to track seen encodings
	seen := make(map[string]struct {
		epoch      uint32
		chainIndex uint8
		posInChain uint8
	})
	
	// Test with random inputs
	for i := 0; i < 100000; i++ {
		var epoch uint32
		var chainIndex, posInChain uint8
		
		binary.Read(rand.Reader, binary.BigEndian, &epoch)
		binary.Read(rand.Reader, binary.BigEndian, &chainIndex)
		binary.Read(rand.Reader, binary.BigEndian, &posInChain)
		
		tweak := ChainTweak(epoch, chainIndex, posInChain)
		key := string(tweak)
		
		if prev, exists := seen[key]; exists {
			if prev.epoch != epoch || prev.chainIndex != chainIndex || prev.posInChain != posInChain {
				t.Fatalf("Collision detected: (%d,%d,%d) and (%d,%d,%d) map to same tweak",
					prev.epoch, prev.chainIndex, prev.posInChain,
					epoch, chainIndex, posInChain)
			}
		}
		seen[key] = struct {
			epoch      uint32
			chainIndex uint8
			posInChain uint8
		}{epoch, chainIndex, posInChain}
	}
	
	// Test with fixed epoch
	seen = make(map[string]struct {
		epoch      uint32
		chainIndex uint8
		posInChain uint8
	})
	
	var fixedEpoch uint32
	binary.Read(rand.Reader, binary.BigEndian, &fixedEpoch)
	for i := 0; i < 10000; i++ {
		var chainIndex, posInChain uint8
		binary.Read(rand.Reader, binary.BigEndian, &chainIndex)
		binary.Read(rand.Reader, binary.BigEndian, &posInChain)
		
		tweak := ChainTweak(fixedEpoch, chainIndex, posInChain)
		key := string(tweak)
		
		if prev, exists := seen[key]; exists {
			if prev.chainIndex != chainIndex || prev.posInChain != posInChain {
				t.Fatalf("Collision with fixed epoch: (%d,%d) and (%d,%d)",
					prev.chainIndex, prev.posInChain,
					chainIndex, posInChain)
			}
		}
		seen[key] = struct {
			epoch      uint32
			chainIndex uint8
			posInChain uint8
		}{fixedEpoch, chainIndex, posInChain}
	}
}

func TestTreeTweakInjective(t *testing.T) {
	// Map to track seen encodings
	seen := make(map[string]struct {
		level      uint8
		posInLevel uint32
	})
	
	// Test with random inputs
	for i := 0; i < 100000; i++ {
		var level uint8
		var posInLevel uint32
		
		binary.Read(rand.Reader, binary.BigEndian, &level)
		binary.Read(rand.Reader, binary.BigEndian, &posInLevel)
		
		tweak := TreeTweak(level, posInLevel)
		key := string(tweak)
		
		if prev, exists := seen[key]; exists {
			if prev.level != level || prev.posInLevel != posInLevel {
				t.Fatalf("Collision detected: (%d,%d) and (%d,%d) map to same tweak",
					prev.level, prev.posInLevel, level, posInLevel)
			}
		}
		seen[key] = struct {
			level      uint8
			posInLevel uint32
		}{level, posInLevel}
	}
	
	// Test with fixed level
	seen = make(map[string]struct {
		level      uint8
		posInLevel uint32
	})
	
	var fixedLevel uint8
	binary.Read(rand.Reader, binary.BigEndian, &fixedLevel)
	for i := 0; i < 10000; i++ {
		var posInLevel uint32
		binary.Read(rand.Reader, binary.BigEndian, &posInLevel)
		
		tweak := TreeTweak(fixedLevel, posInLevel)
		key := string(tweak)
		
		if prev, exists := seen[key]; exists {
			if prev.posInLevel != posInLevel {
				t.Fatalf("Collision with fixed level: %d and %d",
					prev.posInLevel, posInLevel)
			}
		}
		seen[key] = struct {
			level      uint8
			posInLevel uint32
		}{fixedLevel, posInLevel}
	}
}

// Test that tree and chain tweaks are disjoint
func TestTweakDomainsDisjoint(t *testing.T) {
	// Chain tweak should start with 0x00
	chainTweak := ChainTweak(123, 45, 67)
	if chainTweak[0] != 0x00 {
		t.Fatalf("Chain tweak should start with 0x00, got 0x%02x", chainTweak[0])
	}
	
	// Tree tweak should start with 0x01
	treeTweak := TreeTweak(12, 3456)
	if treeTweak[0] != 0x01 {
		t.Fatalf("Tree tweak should start with 0x01, got 0x%02x", treeTweak[0])
	}
	
	// Message tweak should start with 0x02
	msgTweak := MessageTweak(789)
	if msgTweak[0] != 0x02 {
		t.Fatalf("Message tweak should start with 0x02, got 0x%02x", msgTweak[0])
	}
	
	// Ensure they're different lengths too
	if len(chainTweak) == len(treeTweak) && len(chainTweak) == len(msgTweak) {
		t.Log("Warning: All tweaks have same length, relying only on prefix for separation")
	}
}

// Test exact encoding format matches Rust implementation
func TestChainTweakFormat(t *testing.T) {
	// Test specific values to ensure format matches Rust
	tweak := ChainTweak(0x12345678, 0xAB, 0xCD)
	
	expected := []byte{
		0x00,                   // Separator
		0x12, 0x34, 0x56, 0x78, // Epoch (big-endian)
		0xAB, // Chain index
		0xCD, // Position in chain
	}
	
	if !bytes.Equal(tweak, expected) {
		t.Fatalf("ChainTweak format mismatch\nGot:      %x\nExpected: %x", tweak, expected)
	}
}

func TestTreeTweakFormat(t *testing.T) {
	// Test specific values to ensure format matches Rust
	tweak := TreeTweak(0xAB, 0x12345678)
	
	expected := []byte{
		0x01,                   // Separator
		0xAB,                   // Level
		0x12, 0x34, 0x56, 0x78, // Position in level (big-endian)
	}
	
	if !bytes.Equal(tweak, expected) {
		t.Fatalf("TreeTweak format mismatch\nGot:      %x\nExpected: %x", tweak, expected)
	}
}

func TestMessageTweakFormat(t *testing.T) {
	// Test specific values to ensure format matches Rust
	tweak := MessageTweak(0x12345678)
	
	expected := []byte{
		0x02,                   // Separator
		0x78, 0x56, 0x34, 0x12, // Epoch (little-endian) - matches Rust!
	}
	
	if !bytes.Equal(tweak, expected) {
		t.Fatalf("MessageTweak format mismatch\nGot:      %x\nExpected: %x", tweak, expected)
	}
}