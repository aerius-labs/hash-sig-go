package merkle

import (
	"crypto/rand"
	"io"
	"sync"
	
	"github.com/aerius-labs/hash-sig-go/th"
)

// HashTreeLayer represents a single layer in the sparse hash tree
type HashTreeLayer struct {
	startIndex int
	nodes      []th.Domain
}

// GetStartIndex returns the start index of the layer
func (l *HashTreeLayer) GetStartIndex() int {
	return l.startIndex
}

// GetNodes returns the nodes in the layer
func (l *HashTreeLayer) GetNodes() []th.Domain {
	return l.nodes
}

// NewHashTreeLayer creates a new HashTreeLayer
func NewHashTreeLayer(startIndex int, nodes []th.Domain) HashTreeLayer {
	return HashTreeLayer{
		startIndex: startIndex,
		nodes:      nodes,
	}
}

// padded creates a padded layer ensuring start is even and end is odd
func (l *HashTreeLayer) padded(rng io.Reader, thash th.TweakableHash, nodes []th.Domain, startIndex int) *HashTreeLayer {
	endIndex := startIndex + len(nodes) - 1
	
	// Check if we need front padding (start must be even)
	needsFront := (startIndex & 1) == 1
	// Check if we need back padding (end must be odd)
	needsBack := (endIndex & 1) == 0
	
	actualStartIndex := startIndex
	if needsFront {
		actualStartIndex--
	}
	
	// Build padded nodes
	var paddedNodes []th.Domain
	
	if needsFront {
		paddedNodes = append(paddedNodes, thash.RandDomain(rng))
	}
	
	paddedNodes = append(paddedNodes, nodes...)
	
	if needsBack {
		paddedNodes = append(paddedNodes, thash.RandDomain(rng))
	}
	
	return &HashTreeLayer{
		startIndex: actualStartIndex,
		nodes:      paddedNodes,
	}
}

// HashTree represents a sparse Merkle tree (Construction 1)
type HashTree struct {
	depth  int
	layers []HashTreeLayer
	th     th.TweakableHash
	params th.Params
}

// GetDepth returns the depth of the tree
func (t *HashTree) GetDepth() int {
	return t.depth
}

// GetLayers returns the layers of the tree
func (t *HashTree) GetLayers() []HashTreeLayer {
	return t.layers
}

// NewHashTreeFromLayers reconstructs a HashTree from serialized data
func NewHashTreeFromLayers(depth int, layers []HashTreeLayer, params th.Params, thash th.TweakableHash) *HashTree {
	if thash == nil {
		panic("TweakableHash cannot be nil - required for tree operations")
	}
	return &HashTree{
		depth:  depth,
		layers: layers,
		params: params,
		th:     thash,
	}
}

// HashTreeOpening represents a Merkle authentication path
type HashTreeOpening struct {
	CoPath []th.Domain
}

// NewHashTree builds a new sparse hash tree
func NewHashTree(rng io.Reader, thash th.TweakableHash, depth int, startIndex int, 
	parameter th.Params, leafHashes []th.Domain) *HashTree {
	
	if startIndex+len(leafHashes) > (1 << depth) {
		panic("not enough space for leaves")
	}
	
	layers := make([]HashTreeLayer, 0, depth+1)
	
	// Start with the leaf layer, padded accordingly
	layer := (&HashTreeLayer{}).padded(rng, thash, leafHashes, startIndex)
	layers = append(layers, *layer)
	
	// Build tree layer by layer
	for level := 0; level < depth; level++ {
		prev := &layers[level]
		parentStart := prev.startIndex >> 1
		
		// Hash pairs in parallel
		numParents := len(prev.nodes) / 2
		parents := make([]th.Domain, numParents)
		
		// Use goroutines for parallel hashing if we have many nodes
		if numParents > 100 {
			var wg sync.WaitGroup
			wg.Add(numParents)
			
			for i := 0; i < numParents; i++ {
				go func(idx int) {
					defer wg.Done()
					posInLevel := uint32(parentStart + idx)
					tweak := thash.TreeTweak(uint8(level+1), posInLevel)
					children := []th.Domain{
						prev.nodes[2*idx],
						prev.nodes[2*idx+1],
					}
					parents[idx] = thash.Apply(parameter, tweak, children)
				}(i)
			}
			wg.Wait()
		} else {
			// Sequential for small trees
			for i := 0; i < numParents; i++ {
				posInLevel := uint32(parentStart + i)
				tweak := thash.TreeTweak(uint8(level+1), posInLevel)
				children := []th.Domain{
					prev.nodes[2*i],
					prev.nodes[2*i+1],
				}
				parents[i] = thash.Apply(parameter, tweak, children)
			}
		}
		
		// Pad the parent layer
		parentLayer := (&HashTreeLayer{}).padded(rng, thash, parents, parentStart)
		layers = append(layers, *parentLayer)
	}
	
	return &HashTree{
		depth:  depth,
		layers: layers,
		th:     thash,
		params: parameter,
	}
}

// Root returns the root hash of the tree
func (t *HashTree) Root() th.Domain {
	if len(t.layers) == 0 {
		return nil
	}
	rootLayer := &t.layers[len(t.layers)-1]
	if len(rootLayer.nodes) == 0 {
		return nil
	}
	return rootLayer.nodes[0]
}

// Path returns the authentication path for a given epoch
func (t *HashTree) Path(epoch uint32) HashTreeOpening {
	leafIndex := int(epoch)
	coPath := make([]th.Domain, 0, t.depth)
	
	// Start from the leaf layer
	currentIndex := leafIndex
	
	for level := 0; level < t.depth; level++ {
		layer := &t.layers[level]
		
		// Adjust index relative to layer start
		relIndex := currentIndex - layer.startIndex
		
		// Find sibling
		siblingRelIndex := relIndex ^ 1
		
		if siblingRelIndex >= 0 && siblingRelIndex < len(layer.nodes) {
			coPath = append(coPath, layer.nodes[siblingRelIndex])
		} else {
			// Should not happen with proper padding
			coPath = append(coPath, t.th.RandDomain(rand.Reader))
		}
		
		// Move to parent index for next level
		currentIndex = currentIndex >> 1
	}
	
	return HashTreeOpening{CoPath: coPath}
}

// VerifyPath verifies a Merkle authentication path
func VerifyPath(thash th.TweakableHash, parameter th.Params, root th.Domain, 
	epoch uint32, leaf []th.Domain, path HashTreeOpening) bool {
	
	// Hash the leaf first
	leafTweak := thash.TreeTweak(0, epoch)
	current := thash.Apply(parameter, leafTweak, leaf)
	
	// Walk up the tree
	index := epoch
	for level := 0; level < len(path.CoPath); level++ {
		var children []th.Domain
		if (index & 1) == 0 {
			// Current is left child
			children = []th.Domain{current, path.CoPath[level]}
		} else {
			// Current is right child
			children = []th.Domain{path.CoPath[level], current}
		}
		
		parentIndex := index >> 1
		tweak := thash.TreeTweak(uint8(level+1), parentIndex)
		current = thash.Apply(parameter, tweak, children)
		
		index = parentIndex
	}
	
	// Compare with root
	if len(current) != len(root) {
		return false
	}
	for i := range current {
		if current[i] != root[i] {
			return false
		}
	}
	return true
}