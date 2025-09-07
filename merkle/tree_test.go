package merkle

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
	
	"github.com/aerius-labs/hash-sig-go/th"
	"github.com/aerius-labs/hash-sig-go/th/tweak_hash"
)

// Test basic Merkle tree construction
func TestMerkleTreeConstruction(t *testing.T) {
	thash := tweak_hash.NewSHA3TweakableHash(24, 24)
	param := thash.RandParameter(rand.Reader)
	
	// Create raw leaf data (in XMSS, this would be chain ends)
	numLeaves := 8
	leafData := make([][]th.Domain, numLeaves)
	leafHashes := make([]th.Domain, numLeaves)
	for i := 0; i < numLeaves; i++ {
		// Create some leaf data (simulating chain ends)
		leafData[i] = []th.Domain{thash.RandDomain(rand.Reader)}
		// Hash it to get the leaf hash for the tree
		leafTweak := thash.TreeTweak(0, uint32(i))
		leafHashes[i] = thash.Apply(param, leafTweak, leafData[i])
	}
	
	// Build tree with depth 3 (supports up to 8 leaves)
	tree := NewHashTree(rand.Reader, thash, 3, 0, param, leafHashes)
	
	root := tree.Root()
	if len(root) != 24 {
		t.Fatalf("Root should be 24 bytes, got %d", len(root))
	}
	
	// Verify paths for each leaf
	for i := uint32(0); i < uint32(numLeaves); i++ {
		path := tree.Path(i)
		if len(path.CoPath) != 3 {
			t.Fatalf("Path should have depth 3, got %d", len(path.CoPath))
		}
		
		// Verify the path with the original leaf data
		if !VerifyPath(thash, param, root, i, leafData[i], path) {
			t.Fatalf("Path verification failed for leaf %d", i)
		}
	}
}

// Test sparse tree with non-zero start index
func TestSparseTree(t *testing.T) {
	thash := tweak_hash.NewSHA3TweakableHash(16, 24)
	param := thash.RandParameter(rand.Reader)
	
	// Create a sparse tree starting at index 10
	startIndex := 10
	numLeaves := 5
	leafData := make([][]th.Domain, numLeaves)
	leafHashes := make([]th.Domain, numLeaves)
	for i := 0; i < numLeaves; i++ {
		leafData[i] = []th.Domain{thash.RandDomain(rand.Reader)}
		leafTweak := thash.TreeTweak(0, uint32(startIndex+i))
		leafHashes[i] = thash.Apply(param, leafTweak, leafData[i])
	}
	
	// Build tree with depth 5 (supports up to 32 leaves)
	tree := NewHashTree(rand.Reader, thash, 5, startIndex, param, leafHashes)
	
	root := tree.Root()
	
	// Verify paths for the sparse leaves
	for i := 0; i < numLeaves; i++ {
		epoch := uint32(startIndex + i)
		path := tree.Path(epoch)
		
		if !VerifyPath(thash, param, root, epoch, leafData[i], path) {
			t.Fatalf("Path verification failed for sparse leaf at epoch %d", epoch)
		}
	}
}

// Test tree with power-of-2 number of leaves
func TestPowerOfTwoLeaves(t *testing.T) {
	thash := tweak_hash.NewSHA3TweakableHash(24, 24)
	param := thash.RandParameter(rand.Reader)
	
	powers := []int{1, 2, 4, 8, 16}
	
	for _, numLeaves := range powers {
		t.Run(fmt.Sprintf("%d_leaves", numLeaves), func(t *testing.T) {
			leafData := make([][]th.Domain, numLeaves)
			leafHashes := make([]th.Domain, numLeaves)
			for i := 0; i < numLeaves; i++ {
				leafData[i] = []th.Domain{thash.RandDomain(rand.Reader)}
				leafTweak := thash.TreeTweak(0, uint32(i))
				leafHashes[i] = thash.Apply(param, leafTweak, leafData[i])
			}
			
			// Calculate minimum required depth
			depth := 0
			for (1 << depth) < numLeaves {
				depth++
			}
			
			tree := NewHashTree(rand.Reader, thash, depth, 0, param, leafHashes)
			root := tree.Root()
			
			// Verify all paths
			for i := 0; i < numLeaves; i++ {
				path := tree.Path(uint32(i))
				if !VerifyPath(thash, param, root, uint32(i), leafData[i], path) {
					t.Fatalf("Verification failed for leaf %d with %d total leaves", i, numLeaves)
				}
			}
		})
	}
}

// Test tree with odd number of leaves (requires padding)
func TestOddNumberOfLeaves(t *testing.T) {
	thash := tweak_hash.NewSHA3TweakableHash(16, 24)
	param := thash.RandParameter(rand.Reader)
	
	oddCounts := []int{3, 5, 7, 9, 11}
	
	for _, numLeaves := range oddCounts {
		t.Run(fmt.Sprintf("%d_leaves", numLeaves), func(t *testing.T) {
			leafData := make([][]th.Domain, numLeaves)
			leafHashes := make([]th.Domain, numLeaves)
			for i := 0; i < numLeaves; i++ {
				leafData[i] = []th.Domain{thash.RandDomain(rand.Reader)}
				leafTweak := thash.TreeTweak(0, uint32(i))
				leafHashes[i] = thash.Apply(param, leafTweak, leafData[i])
			}
			
			// Calculate minimum required depth
			depth := 0
			for (1 << depth) < numLeaves {
				depth++
			}
			
			tree := NewHashTree(rand.Reader, thash, depth, 0, param, leafHashes)
			root := tree.Root()
			
			// Verify paths for actual leaves
			for i := 0; i < numLeaves; i++ {
				path := tree.Path(uint32(i))
				if !VerifyPath(thash, param, root, uint32(i), leafData[i], path) {
					t.Fatalf("Verification failed for leaf %d with %d total leaves", i, numLeaves)
				}
			}
		})
	}
}

// Test that different trees produce different roots
func TestTreeUniqueness(t *testing.T) {
	thash := tweak_hash.NewSHA3TweakableHash(24, 24)
	
	numTrees := 10
	roots := make([]th.Domain, numTrees)
	
	for i := 0; i < numTrees; i++ {
		param := thash.RandParameter(rand.Reader)
		
		leafHashes := make([]th.Domain, 4)
		for j := 0; j < 4; j++ {
			leafData := []th.Domain{thash.RandDomain(rand.Reader)}
			leafTweak := thash.TreeTweak(0, uint32(j))
			leafHashes[j] = thash.Apply(param, leafTweak, leafData)
		}
		
		tree := NewHashTree(rand.Reader, thash, 2, 0, param, leafHashes)
		roots[i] = tree.Root()
	}
	
	// Check all roots are unique
	for i := 0; i < numTrees; i++ {
		for j := i + 1; j < numTrees; j++ {
			if bytes.Equal(roots[i], roots[j]) {
				t.Fatalf("Trees %d and %d have identical roots", i, j)
			}
		}
	}
}

// Test incorrect path verification fails
func TestIncorrectPathFails(t *testing.T) {
	thash := tweak_hash.NewSHA3TweakableHash(24, 24)
	param := thash.RandParameter(rand.Reader)
	
	leafData := make([][]th.Domain, 4)
	leafHashes := make([]th.Domain, 4)
	for i := 0; i < 4; i++ {
		leafData[i] = []th.Domain{thash.RandDomain(rand.Reader)}
		leafTweak := thash.TreeTweak(0, uint32(i))
		leafHashes[i] = thash.Apply(param, leafTweak, leafData[i])
	}
	
	tree := NewHashTree(rand.Reader, thash, 2, 0, param, leafHashes)
	root := tree.Root()
	
	// Get valid path for leaf 0
	path0 := tree.Path(0)
	
	// Try to verify with wrong leaf
	if VerifyPath(thash, param, root, 0, leafData[1], path0) {
		t.Fatal("Verification should fail with wrong leaf")
	}
	
	// Try to verify with wrong epoch
	if VerifyPath(thash, param, root, 1, leafData[0], path0) {
		t.Fatal("Verification should fail with wrong epoch")
	}
	
	// Try to verify with corrupted path
	corruptedPath := HashTreeOpening{
		CoPath: make([]th.Domain, len(path0.CoPath)),
	}
	for i := range corruptedPath.CoPath {
		corruptedPath.CoPath[i] = thash.RandDomain(rand.Reader)
	}
	if VerifyPath(thash, param, root, 0, leafData[0], corruptedPath) {
		t.Fatal("Verification should fail with corrupted path")
	}
}

// Benchmark tree construction
func BenchmarkTreeConstruction(b *testing.B) {
	thash := tweak_hash.NewSHA3TweakableHash(24, 24)
	param := thash.RandParameter(rand.Reader)
	
	sizes := []int{16, 64, 256}
	
	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size%d", size), func(b *testing.B) {
			leafHashes := make([]th.Domain, size)
			for i := 0; i < size; i++ {
				leafData := []th.Domain{thash.RandDomain(rand.Reader)}
				leafTweak := thash.TreeTweak(0, uint32(i))
				leafHashes[i] = thash.Apply(param, leafTweak, leafData)
			}
			
			// Calculate required depth
			depth := 0
			for (1 << depth) < size {
				depth++
			}
			
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				NewHashTree(rand.Reader, thash, depth, 0, param, leafHashes)
			}
		})
	}
}

// Benchmark path verification
func BenchmarkPathVerification(b *testing.B) {
	thash := tweak_hash.NewSHA3TweakableHash(24, 24)
	param := thash.RandParameter(rand.Reader)
	
	leafData := make([][]th.Domain, 256)
	leafHashes := make([]th.Domain, 256)
	for i := 0; i < 256; i++ {
		leafData[i] = []th.Domain{thash.RandDomain(rand.Reader)}
		leafTweak := thash.TreeTweak(0, uint32(i))
		leafHashes[i] = thash.Apply(param, leafTweak, leafData[i])
	}
	
	tree := NewHashTree(rand.Reader, thash, 8, 0, param, leafHashes)
	root := tree.Root()
	path := tree.Path(128)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyPath(thash, param, root, 128, leafData[128], path)
	}
}