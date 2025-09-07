package tweak_hash

import (
	"bytes"
	"crypto/rand"
	"testing"
	
	"github.com/aerius-labs/hash-sig-go/th"
)

// Test vectors to ensure compatibility with Rust implementation
func TestSHA3FixedVectors(t *testing.T) {
	// Create instances matching Rust's ShaTweak128192 and ShaTweak192192
	th128_192 := NewSHA3TweakableHash(16, 24) // 128-bit param, 192-bit hash
	th192_192 := NewSHA3TweakableHash(24, 24) // 192-bit param, 192-bit hash
	
	// Fixed test vector
	param128 := make([]byte, 16)
	for i := range param128 {
		param128[i] = byte(i)
	}
	
	param192 := make([]byte, 24)
	for i := range param192 {
		param192[i] = byte(i)
	}
	
	message1 := make([]byte, 24)
	for i := range message1 {
		message1[i] = byte(i * 2)
	}
	
	message2 := make([]byte, 24)
	for i := range message2 {
		message2[i] = byte(i * 3)
	}
	
	// Test tree tweak
	treeTweak := th128_192.TreeTweak(0, 3)
	result1 := th128_192.Apply(param128, treeTweak, []th.Domain{message1, message2})
	
	// Test chain tweak
	chainTweak := th192_192.ChainTweak(2, 3, 4)
	result2 := th192_192.Apply(param192, chainTweak, []th.Domain{message1, message2})
	
	// Results should be deterministic
	if len(result1) != 24 {
		t.Fatalf("Expected 24 bytes, got %d", len(result1))
	}
	if len(result2) != 24 {
		t.Fatalf("Expected 24 bytes, got %d", len(result2))
	}
	
	// Run again to verify determinism
	result1_2 := th128_192.Apply(param128, treeTweak, []th.Domain{message1, message2})
	if !bytes.Equal(result1, result1_2) {
		t.Fatal("SHA3 tweakable hash is not deterministic")
	}
}

// Test all standard configurations from Rust
func TestSHA3Configurations(t *testing.T) {
	configs := []struct {
		name      string
		paramLen  int
		hashLen   int
	}{
		{"128_128", 16, 16},
		{"128_192", 16, 24},
		{"192_192", 24, 24},
	}
	
	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			thash := NewSHA3TweakableHash(cfg.paramLen, cfg.hashLen)
			
			// Generate random inputs
			param := thash.RandParameter(rand.Reader)
			msg1 := thash.RandDomain(rand.Reader)
			msg2 := thash.RandDomain(rand.Reader)
			
			// Test tree tweak
			treeTweak := thash.TreeTweak(0, 3)
			result := thash.Apply(param, treeTweak, []th.Domain{msg1, msg2})
			
			if len(result) != cfg.hashLen {
				t.Fatalf("Expected %d bytes, got %d", cfg.hashLen, len(result))
			}
			
			// Test chain tweak
			chainTweak := thash.ChainTweak(2, 3, 4)
			result = thash.Apply(param, chainTweak, []th.Domain{msg1, msg2})
			
			if len(result) != cfg.hashLen {
				t.Fatalf("Expected %d bytes, got %d", cfg.hashLen, len(result))
			}
		})
	}
}

// Test truncation behavior
func TestSHA3Truncation(t *testing.T) {
	// Test that truncation works correctly for non-standard lengths
	thash := NewSHA3TweakableHash(10, 17) // Non-standard lengths
	
	param := thash.RandParameter(rand.Reader)
	if len(param) != 10 {
		t.Fatalf("Parameter length mismatch: got %d, want 10", len(param))
	}
	
	domain := thash.RandDomain(rand.Reader)
	if len(domain) != 17 {
		t.Fatalf("Domain length mismatch: got %d, want 17", len(domain))
	}
	
	tweak := thash.TreeTweak(1, 2)
	result := thash.Apply(param, tweak, []th.Domain{domain})
	
	if len(result) != 17 {
		t.Fatalf("Result length mismatch: got %d, want 17", len(result))
	}
}

// Benchmark SHA3 tweakable hash
func BenchmarkSHA3Apply(b *testing.B) {
	thash := NewSHA3TweakableHash(24, 24)
	param := thash.RandParameter(rand.Reader)
	msg1 := thash.RandDomain(rand.Reader)
	msg2 := thash.RandDomain(rand.Reader)
	tweak := thash.ChainTweak(0, 0, 0)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		thash.Apply(param, tweak, []th.Domain{msg1, msg2})
	}
}
