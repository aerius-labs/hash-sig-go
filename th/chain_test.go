package th

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	
	"golang.org/x/crypto/sha3"
)

// mockTweakableHash is a simple mock for testing
type mockTweakableHash struct {
	paramLen int
	hashLen  int
}

func (m *mockTweakableHash) RandParameter(rng io.Reader) Params {
	p := make([]byte, m.paramLen)
	io.ReadFull(rng, p)
	return p
}

func (m *mockTweakableHash) RandDomain(rng io.Reader) Domain {
	d := make([]byte, m.hashLen)
	io.ReadFull(rng, d)
	return d
}

func (m *mockTweakableHash) TreeTweak(level uint8, posInLevel uint32) Tweak {
	tweak := make([]byte, 0, 6)
	tweak = append(tweak, TweakSeparatorTreeHash)
	tweak = append(tweak, level)
	tweak = append(tweak, byte(posInLevel>>24), byte(posInLevel>>16), byte(posInLevel>>8), byte(posInLevel))
	return tweak
}

func (m *mockTweakableHash) ChainTweak(epoch uint32, chainIndex uint8, posInChain uint8) Tweak {
	tweak := make([]byte, 0, 7)
	tweak = append(tweak, TweakSeparatorChainHash)
	tweak = append(tweak, byte(epoch>>24), byte(epoch>>16), byte(epoch>>8), byte(epoch))
	tweak = append(tweak, chainIndex)
	tweak = append(tweak, posInChain)
	return tweak
}

func (m *mockTweakableHash) Apply(parameter Params, tweak Tweak, message []Domain) Domain {
	h := sha3.New256()
	h.Write(parameter)
	h.Write(tweak)
	for _, msg := range message {
		h.Write(msg)
	}
	result := h.Sum(nil)
	if len(result) > m.hashLen {
		result = result[:m.hashLen]
	}
	return result
}

func (m *mockTweakableHash) OutputLen() int    { return m.hashLen }
func (m *mockTweakableHash) ParameterLen() int { return m.paramLen }

// Test that hash chains are associative (Lemma 2 from the paper)
// Walking a+b steps should equal walking a steps then b steps
func TestChainAssociative(t *testing.T) {
	th := &mockTweakableHash{paramLen: 16, hashLen: 24}
	
	// Fixed test parameters
	epoch := uint32(9)
	chainIndex := uint8(20)
	totalSteps := 16
	
	// Generate random parameter and start
	parameter := th.RandParameter(rand.Reader)
	start := th.RandDomain(rand.Reader)
	
	// Walk directly for total steps
	endDirect := Chain(th, parameter, epoch, chainIndex, 0, totalSteps, start)
	
	// Test all possible splits
	for split := 0; split <= totalSteps; split++ {
		stepsA := split
		stepsB := totalSteps - split
		
		// Walk in two stages
		intermediate := Chain(th, parameter, epoch, chainIndex, 0, stepsA, start)
		endIndirect := Chain(th, parameter, epoch, chainIndex, uint8(stepsA), stepsB, intermediate)
		
		// Should be identical
		if !bytes.Equal(endDirect, endIndirect) {
			t.Fatalf("Chain not associative at split %d: direct != indirect", split)
		}
	}
}

// Test chain with maximum values to ensure no overflow
func TestChainMaxValues(t *testing.T) {
	th := &mockTweakableHash{paramLen: 24, hashLen: 24}
	
	// Test with maximum epoch value
	epoch := uint32(0xFFFFFFFF)
	chainIndex := uint8(255)
	posInChain := uint8(254) // Leave room for one step
	
	parameter := th.RandParameter(rand.Reader)
	start := th.RandDomain(rand.Reader)
	
	// Should not panic
	result := Chain(th, parameter, epoch, chainIndex, posInChain, 1, start)
	if len(result) != 24 {
		t.Fatalf("Expected 24 byte result, got %d", len(result))
	}
}

// Test that chain with 0 steps returns input unchanged
func TestChainZeroSteps(t *testing.T) {
	th := &mockTweakableHash{paramLen: 16, hashLen: 24}
	
	parameter := th.RandParameter(rand.Reader)
	start := th.RandDomain(rand.Reader)
	
	result := Chain(th, parameter, 42, 7, 3, 0, start)
	
	if !bytes.Equal(result, start) {
		t.Fatal("Chain with 0 steps should return input unchanged")
	}
}

// Test chain consistency across multiple runs
func TestChainDeterministic(t *testing.T) {
	th := &mockTweakableHash{paramLen: 16, hashLen: 24}
	
	// Fixed inputs
	parameter := make([]byte, 16)
	for i := range parameter {
		parameter[i] = byte(i)
	}
	
	start := make([]byte, 24)
	for i := range start {
		start[i] = byte(i * 2)
	}
	
	epoch := uint32(123)
	chainIndex := uint8(45)
	startPos := uint8(6)
	steps := 10
	
	// Run multiple times
	result1 := Chain(th, parameter, epoch, chainIndex, startPos, steps, start)
	result2 := Chain(th, parameter, epoch, chainIndex, startPos, steps, start)
	result3 := Chain(th, parameter, epoch, chainIndex, startPos, steps, start)
	
	if !bytes.Equal(result1, result2) || !bytes.Equal(result2, result3) {
		t.Fatal("Chain is not deterministic")
	}
}

// Benchmark chain performance
func BenchmarkChain(b *testing.B) {
	th := &mockTweakableHash{paramLen: 24, hashLen: 24}
	parameter := th.RandParameter(rand.Reader)
	start := th.RandDomain(rand.Reader)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Chain(th, parameter, uint32(i), 0, 0, 16, start)
	}
}

// Test multiple chain lengths
func TestChainVariousLengths(t *testing.T) {
	th := &mockTweakableHash{paramLen: 16, hashLen: 24}
	parameter := th.RandParameter(rand.Reader)
	start := th.RandDomain(rand.Reader)
	
	lengths := []int{1, 2, 4, 8, 16, 32, 64, 128, 255}
	
	for _, length := range lengths {
		result := Chain(th, parameter, 0, 0, 0, length, start)
		if len(result) != 24 {
			t.Fatalf("Chain with %d steps produced wrong length: %d", length, len(result))
		}
		
		// Verify result is different from start (unless length is 0)
		if length > 0 && bytes.Equal(result, start) {
			t.Fatalf("Chain with %d steps should modify input", length)
		}
	}
}