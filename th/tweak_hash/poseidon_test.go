package tweak_hash

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
	
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/aerius-labs/hash-sig-go/th"
)

// Test basic apply functionality
func TestPoseidonTweakHashApply(t *testing.T) {
	// Test both width 16 and 24 variants
	configs := []struct {
		name      string
		paramLen  int
		hashLen   int
		tweakLen  int
		capacity  int
		numChunks int
	}{
		{"Width16", 4, 4, 2, 9, 32},
		{"Width24", 3, 7, 2, 9, 32},
	}
	
	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			pth := NewPoseidonTweakHash(
				cfg.paramLen,
				cfg.hashLen,
				cfg.tweakLen,
				cfg.capacity,
				cfg.numChunks,
			)
			
			// Generate random inputs
			params := pth.RandParameter(rand.Reader)
			msg1 := pth.RandDomain(rand.Reader)
			msg2 := pth.RandDomain(rand.Reader)
			
			// Test tree tweak
			treeTweak := pth.TreeTweak(1, 2)
			result1 := pth.Apply(params, treeTweak, []th.Domain{msg1, msg2})
			
			// Test chain tweak
			chainTweak := pth.ChainTweak(42, 3, 4)
			result2 := pth.Apply(params, chainTweak, []th.Domain{msg1})
			
			// Results should be different
			if bytes.Equal(result1, result2) {
				t.Error("Different tweaks produced same result")
			}
			
			// Test consistency - same inputs should give same output
			result3 := pth.Apply(params, treeTweak, []th.Domain{msg1, msg2})
			if !bytes.Equal(result1, result3) {
				t.Error("Same inputs produced different results")
			}
		})
	}
}

// Test tree tweak field element conversion
func TestTreeTweakFieldElements(t *testing.T) {
	pth := NewPoseidonTweakHash(4, 4, 2, 9, 32)
	
	level := uint8(1)
	posInLevel := uint32(2)
	sep := uint64(TweakSeparatorTreeHash)
	
	// Compute expected bigint: (level << 40) | (posInLevel << 8) | sep
	tweakBigint := new(big.Int)
	tweakBigint.SetUint64(uint64(level) << 40)
	temp := new(big.Int).SetUint64(uint64(posInLevel) << 8)
	tweakBigint.Add(tweakBigint, temp)
	tweakBigint.Add(tweakBigint, new(big.Int).SetUint64(sep))
	
	// Convert to field elements
	p := new(big.Int).SetUint64(2013265921)
	expected := make([]babybear.Element, 2)
	
	remainder := new(big.Int).Set(tweakBigint)
	for i := 0; i < 2; i++ {
		var e babybear.Element
		digit := new(big.Int).Mod(remainder, p)
		e.SetBigInt(digit)
		expected[i] = e
		remainder.Div(remainder, p)
	}
	
	// Get actual from implementation
	tweak := pth.TreeTweak(level, posInLevel)
	actual := pth.tweakToFieldElements(tweak)
	
	// Compare
	for i := 0; i < 2; i++ {
		if !actual[i].Equal(&expected[i]) {
			t.Errorf("Tree tweak field element %d mismatch", i)
		}
	}
}

// Test chain tweak field element conversion
func TestChainTweakFieldElements(t *testing.T) {
	pth := NewPoseidonTweakHash(4, 4, 2, 9, 32)
	
	epoch := uint32(1)
	chainIndex := uint8(2)
	posInChain := uint8(3)
	sep := uint64(TweakSeparatorChainHash)
	
	// Compute expected bigint: (epoch << 24) | (chainIndex << 16) | (posInChain << 8) | sep
	tweakBigint := new(big.Int)
	tweakBigint.SetUint64(uint64(epoch) << 24)
	temp := new(big.Int).SetUint64(uint64(chainIndex) << 16)
	tweakBigint.Add(tweakBigint, temp)
	temp.SetUint64(uint64(posInChain) << 8)
	tweakBigint.Add(tweakBigint, temp)
	tweakBigint.Add(tweakBigint, new(big.Int).SetUint64(sep))
	
	// Convert to field elements
	p := new(big.Int).SetUint64(2013265921)
	expected := make([]babybear.Element, 2)
	
	remainder := new(big.Int).Set(tweakBigint)
	for i := 0; i < 2; i++ {
		var e babybear.Element
		digit := new(big.Int).Mod(remainder, p)
		e.SetBigInt(digit)
		expected[i] = e
		remainder.Div(remainder, p)
	}
	
	// Get actual from implementation
	tweak := pth.ChainTweak(epoch, chainIndex, posInChain)
	actual := pth.tweakToFieldElements(tweak)
	
	// Compare
	for i := 0; i < 2; i++ {
		if !actual[i].Equal(&expected[i]) {
			t.Errorf("Chain tweak field element %d mismatch", i)
		}
	}
}

// Test max values for tweaks
func TestTweakMaxValues(t *testing.T) {
	pth := NewPoseidonTweakHash(4, 4, 2, 9, 32)
	
	t.Run("TreeTweakMax", func(t *testing.T) {
		level := uint8(255)
		posInLevel := uint32(0xFFFFFFFF)
		
		// Should not panic
		tweak := pth.TreeTweak(level, posInLevel)
		fields := pth.tweakToFieldElements(tweak)
		
		if len(fields) != 2 {
			t.Errorf("Expected 2 field elements, got %d", len(fields))
		}
	})
	
	t.Run("ChainTweakMax", func(t *testing.T) {
		epoch := uint32(0xFFFFFFFF)
		chainIndex := uint8(255)
		posInChain := uint8(255)
		
		// Should not panic
		tweak := pth.ChainTweak(epoch, chainIndex, posInChain)
		fields := pth.tweakToFieldElements(tweak)
		
		if len(fields) != 2 {
			t.Errorf("Expected 2 field elements, got %d", len(fields))
		}
	})
}

// Test tweak injectivity - different inputs should give different outputs
func TestTweakInjectivity(t *testing.T) {
	pth := NewPoseidonTweakHash(4, 4, 2, 9, 32)
	
	t.Run("TreeTweakInjective", func(t *testing.T) {
		seen := make(map[string]struct{})
		
		// Test many random values
		for i := 0; i < 10000; i++ {
			var level uint8
			var posInLevel uint32
			
			b := make([]byte, 5)
			rand.Read(b)
			level = b[0]
			posInLevel = uint32(b[1])<<24 | uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4])
			
			tweak := pth.TreeTweak(level, posInLevel)
			fields := pth.tweakToFieldElements(tweak)
			
			// Convert to string for map key
			key := ""
			for _, f := range fields {
				key += f.String() + ","
			}
			
			if _, exists := seen[key]; exists {
				t.Fatalf("Collision found for level=%d, pos=%d", level, posInLevel)
			}
			seen[key] = struct{}{}
		}
	})
	
	t.Run("ChainTweakInjective", func(t *testing.T) {
		seen := make(map[string]struct{})
		
		// Test many random values
		for i := 0; i < 10000; i++ {
			var epoch uint32
			var chainIndex, posInChain uint8
			
			b := make([]byte, 6)
			rand.Read(b)
			epoch = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
			chainIndex = b[4]
			posInChain = b[5]
			
			tweak := pth.ChainTweak(epoch, chainIndex, posInChain)
			fields := pth.tweakToFieldElements(tweak)
			
			// Convert to string for map key
			key := ""
			for _, f := range fields {
				key += f.String() + ","
			}
			
			if _, exists := seen[key]; exists {
				t.Fatalf("Collision found for epoch=%d, chain=%d, pos=%d", 
					epoch, chainIndex, posInChain)
			}
			seen[key] = struct{}{}
		}
	})
}

// Test that random parameters are not all the same
func TestRandParameterNotAllSame(t *testing.T) {
	pth := NewPoseidonTweakHash(4, 4, 2, 9, 32)
	
	allSameCount := 0
	trials := 10
	
	for i := 0; i < trials; i++ {
		params := pth.RandParameter(rand.Reader)
		
		// Check if all bytes are identical
		if len(params) > 0 {
			first := params[0]
			allSame := true
			for _, b := range params[1:] {
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
		t.Error("All random parameters had identical bytes")
	}
}

// Test that random domain elements are not all the same
func TestRandDomainNotAllSame(t *testing.T) {
	pth := NewPoseidonTweakHash(4, 4, 2, 9, 32)
	
	allSameCount := 0
	trials := 10
	
	for i := 0; i < trials; i++ {
		domain := pth.RandDomain(rand.Reader)
		
		// Check if all bytes are identical
		if len(domain) > 0 {
			first := domain[0]
			allSame := true
			for _, b := range domain[1:] {
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
		t.Error("All random domain elements had identical bytes")
	}
}