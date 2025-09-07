package xmss

import (
	"crypto/rand"
	"testing"
	
	"github.com/aerius-labs/hash-sig-go/encoding/winternitz"
	"github.com/aerius-labs/hash-sig-go/encoding/targetsum"
	"github.com/aerius-labs/hash-sig-go/internal/prf"
	"github.com/aerius-labs/hash-sig-go/th/tweak_hash"
	"github.com/aerius-labs/hash-sig-go/th/message_hash"
)

func TestWinternitzXMSS(t *testing.T) {
	// Setup similar to Rust test_winternitz
	// PRF with 24 byte key, 24 byte output
	prfInstance := prf.NewSHA3PRF(24, 24)
	
	// Tweakable hash with 24 byte parameter, 24 byte output
	thInstance := tweak_hash.NewSHA3TweakableHash(24, 24)
	
	// Message hash: 24 byte param, 24 byte randomness, 48 chunks of 4 bits
	mhInstance := message_hash.NewSHA3MessageHash(24, 24, 48, 4)
	
	// Winternitz encoding with checksum
	// For 48 chunks of 4 bits, max checksum = 48 * 15 = 720
	// log_16(720) = 2.something, so we need 3 checksum chunks
	encInstance := winternitz.NewWinternitzEncoding(mhInstance, 4, 3)
	
	// Create XMSS with log lifetime = 9 (512 epochs)
	xmss := NewGeneralizedXMSS(prfInstance, encInstance, thInstance, 9)
	
	// Generate key pair
	pk, sk := xmss.KeyGen(rand.Reader, 0, int(xmss.Lifetime()))
	
	// Test signing and verification at different epochs
	testEpochs := []uint32{0, 2, 11, 19, 289}
	
	for _, epoch := range testEpochs {
		// Generate random message
		message := make([]byte, 32)
		if _, err := rand.Read(message); err != nil {
			t.Fatalf("Failed to generate random message: %v", err)
		}
		
		// Sign message
		sig, err := xmss.Sign(rand.Reader, sk, epoch, message)
		if err != nil {
			t.Fatalf("Failed to sign at epoch %d: %v", epoch, err)
		}
		
		// Verify signature
		if !xmss.Verify(pk, epoch, message, sig) {
			t.Fatalf("Signature verification failed at epoch %d", epoch)
		}
		
		// Test with wrong message should fail
		wrongMessage := make([]byte, 32)
		if _, err := rand.Read(wrongMessage); err != nil {
			t.Fatalf("Failed to generate wrong message: %v", err)
		}
		
		if xmss.Verify(pk, epoch, wrongMessage, sig) {
			t.Fatalf("Signature verification should have failed for wrong message at epoch %d", epoch)
		}
		
		// Test with wrong epoch should fail
		wrongEpoch := epoch + 1
		if wrongEpoch < uint32(xmss.Lifetime()) {
			if xmss.Verify(pk, wrongEpoch, message, sig) {
				t.Fatalf("Signature verification should have failed for wrong epoch")
			}
		}
	}
}

func TestTargetSumXMSS(t *testing.T) {
	// Setup similar to Rust test_target_sum
	prfInstance := prf.NewSHA3PRF(24, 24)
	thInstance := tweak_hash.NewSHA3TweakableHash(24, 24)
	mhInstance := message_hash.NewSHA3MessageHash(24, 24, 48, 4)
	
	// Target sum encoding
	// For 48 chunks of 4 bits, expected sum = 48 * 15 / 2 = 360
	targetSum := targetsum.ComputeOptimalTarget(48, 4, 1.0)
	encInstance := targetsum.NewTargetSumEncoding(mhInstance, targetSum)
	
	// Create XMSS with log lifetime = 8 (256 epochs)
	xmss := NewGeneralizedXMSS(prfInstance, encInstance, thInstance, 8)
	
	// Generate key pair
	pk, sk := xmss.KeyGen(rand.Reader, 0, int(xmss.Lifetime()))
	
	// Test signing and verification
	testEpochs := []uint32{0, 9, 13, 21, 31}
	
	for _, epoch := range testEpochs {
		// Generate random message
		message := make([]byte, 32)
		if _, err := rand.Read(message); err != nil {
			t.Fatalf("Failed to generate random message: %v", err)
		}
		
		// Sign message (may need retries for target sum)
		sig, err := xmss.Sign(rand.Reader, sk, epoch, message)
		if err != nil {
			t.Fatalf("Failed to sign at epoch %d: %v", epoch, err)
		}
		
		// Verify signature
		if !xmss.Verify(pk, epoch, message, sig) {
			t.Fatalf("Signature verification failed at epoch %d", epoch)
		}
	}
}

func TestPartialLifetime(t *testing.T) {
	// Test with partial lifetime activation
	prfInstance := prf.NewSHA3PRF(24, 24)
	thInstance := tweak_hash.NewSHA3TweakableHash(24, 24)
	mhInstance := message_hash.NewSHA3MessageHash(24, 24, 48, 4)
	encInstance := winternitz.NewWinternitzEncoding(mhInstance, 4, 3)
	
	xmss := NewGeneralizedXMSS(prfInstance, encInstance, thInstance, 5) // 32 epochs total
	
	// Generate key pair active for epochs 10-20
	activationEpoch := 10
	numActiveEpochs := 10
	pk, sk := xmss.KeyGen(rand.Reader, activationEpoch, numActiveEpochs)
	
	// Should succeed for epoch 15
	message := make([]byte, 32)
	rand.Read(message)
	
	sig, err := xmss.Sign(rand.Reader, sk, 15, message)
	if err != nil {
		t.Fatalf("Failed to sign at valid epoch: %v", err)
	}
	
	if !xmss.Verify(pk, 15, message, sig) {
		t.Fatal("Verification failed for valid epoch")
	}
	
	// Should fail for epoch 5 (before activation)
	_, err = xmss.Sign(rand.Reader, sk, 5, message)
	if err == nil {
		t.Fatal("Signing should have failed for epoch before activation")
	}
	
	// Should fail for epoch 25 (after expiration)
	_, err = xmss.Sign(rand.Reader, sk, 25, message)
	if err == nil {
		t.Fatal("Signing should have failed for epoch after expiration")
	}
}

func BenchmarkWinternitzSign(b *testing.B) {
	prfInstance := prf.NewSHA3PRF(24, 24)
	thInstance := tweak_hash.NewSHA3TweakableHash(24, 24)
	mhInstance := message_hash.NewSHA3MessageHash(24, 24, 48, 4)
	encInstance := winternitz.NewWinternitzEncoding(mhInstance, 4, 3)
	
	xmss := NewGeneralizedXMSS(prfInstance, encInstance, thInstance, 9)
	_, sk := xmss.KeyGen(rand.Reader, 0, 512)
	
	message := make([]byte, 32)
	rand.Read(message)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		epoch := uint32(i % 512)
		_, err := xmss.Sign(rand.Reader, sk, epoch, message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWinternitzVerify(b *testing.B) {
	prfInstance := prf.NewSHA3PRF(24, 24)
	thInstance := tweak_hash.NewSHA3TweakableHash(24, 24)
	mhInstance := message_hash.NewSHA3MessageHash(24, 24, 48, 4)
	encInstance := winternitz.NewWinternitzEncoding(mhInstance, 4, 3)
	
	xmss := NewGeneralizedXMSS(prfInstance, encInstance, thInstance, 9)
	pk, sk := xmss.KeyGen(rand.Reader, 0, 512)
	
	message := make([]byte, 32)
	rand.Read(message)
	sig, _ := xmss.Sign(rand.Reader, sk, 0, message)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !xmss.Verify(pk, 0, message, sig) {
			b.Fatal("Verification failed")
		}
	}
}