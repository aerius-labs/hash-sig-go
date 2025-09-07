package xmss

import (
	"errors"
	"fmt"
	"io"
	"sync"
	
	"github.com/aerius-labs/hash-sig-go/encoding"
	"github.com/aerius-labs/hash-sig-go/internal/prf"
	"github.com/aerius-labs/hash-sig-go/merkle"
	"github.com/aerius-labs/hash-sig-go/th"
)

// SigningError represents errors during signing
type SigningError struct {
	Message  string
	Attempts int
}

func (e *SigningError) Error() string {
	return fmt.Sprintf("%s after %d attempts", e.Message, e.Attempts)
}

// PublicKey represents a generalized XMSS public key
type PublicKey struct {
	Root      th.Domain
	Parameter th.Params
}

// SecretKey represents a generalized XMSS secret key
type SecretKey struct {
	PRFKey           []byte
	Tree             *merkle.HashTree
	Parameter        th.Params
	ActivationEpoch  int
	NumActiveEpochs  int
}

// Signature represents a generalized XMSS signature
type Signature struct {
	Path   merkle.HashTreeOpening
	Rho    []byte
	Hashes []th.Domain
}

// GeneralizedXMSS implements the generalized XMSS signature scheme (Construction 3)
type GeneralizedXMSS struct {
	prf          prf.PRF
	encoding     encoding.IncomparableEncoding
	th           th.TweakableHash
	logLifetime  int
}

// NewGeneralizedXMSS creates a new generalized XMSS instance
func NewGeneralizedXMSS(
	prf prf.PRF,
	encoding encoding.IncomparableEncoding,
	th th.TweakableHash,
	logLifetime int,
) *GeneralizedXMSS {
	if logLifetime > 32 {
		panic("lifetime beyond 2^32 not supported")
	}
	
	// Verify consistency
	if encoding.Base() > 256 {
		panic("encoding base too large, must be at most 256")
	}
	if encoding.Dimension() > 256 {
		panic("encoding dimension too large, must be at most 256")
	}
	
	return &GeneralizedXMSS{
		prf:         prf,
		encoding:    encoding,
		th:          th,
		logLifetime: logLifetime,
	}
}

// Lifetime returns the maximum number of epochs (L)
func (g *GeneralizedXMSS) Lifetime() uint64 {
	return 1 << g.logLifetime
}

// KeyGen generates a new key pair
func (g *GeneralizedXMSS) KeyGen(rng io.Reader, activationEpoch, numActiveEpochs int) (*PublicKey, *SecretKey) {
	// Validate parameters
	if activationEpoch+numActiveEpochs > int(g.Lifetime()) {
		panic("activation epoch and num active epochs invalid for this lifetime")
	}
	
	// Generate random parameter for tweakable hash
	parameter := g.th.RandParameter(rng)
	
	// Generate PRF key
	prfKey := g.prf.KeyGen(rng)
	
	// Generate chain ends for each active epoch
	numChains := g.encoding.Dimension()
	chainLength := g.encoding.Base()
	
	// Parallelize chain end computation for each epoch
	activationRange := activationEpoch
	
	chainEndsHashes := make([]th.Domain, numActiveEpochs)
	
	// Use goroutines for parallel computation if we have many epochs
	if numActiveEpochs > 10 {
		var wg sync.WaitGroup
		wg.Add(numActiveEpochs)
		
		for i := 0; i < numActiveEpochs; i++ {
			go func(epochOffset int) {
				defer wg.Done()
				epoch := activationRange + epochOffset
				
				// Compute chain ends for this epoch
				chainEnds := make([]th.Domain, numChains)
				for chainIndex := 0; chainIndex < numChains; chainIndex++ {
					// Get chain start from PRF
					start := g.prf.Apply(prfKey, uint32(epoch), uint64(chainIndex))
					// Walk chain to get public chain end
					chainEnds[chainIndex] = th.Chain(
						g.th,
						parameter,
						uint32(epoch),
						uint8(chainIndex),
						0,
						chainLength-1,
						start,
					)
				}
				
				// Hash chain ends to get epoch's public key
				leafTweak := g.th.TreeTweak(0, uint32(epoch))
				chainEndsHashes[epochOffset] = g.th.Apply(parameter, leafTweak, chainEnds)
			}(i)
		}
		wg.Wait()
	} else {
		// Sequential for small number of epochs
		for epochOffset := 0; epochOffset < numActiveEpochs; epochOffset++ {
			epoch := activationRange + epochOffset
			
			chainEnds := make([]th.Domain, numChains)
			for chainIndex := 0; chainIndex < numChains; chainIndex++ {
				start := g.prf.Apply(prfKey, uint32(epoch), uint64(chainIndex))
				chainEnds[chainIndex] = th.Chain(
					g.th,
					parameter,
					uint32(epoch),
					uint8(chainIndex),
					0,
					chainLength-1,
					start,
				)
			}
			
			leafTweak := g.th.TreeTweak(0, uint32(epoch))
			chainEndsHashes[epochOffset] = g.th.Apply(parameter, leafTweak, chainEnds)
		}
	}
	
	// Build Merkle tree
	tree := merkle.NewHashTree(
		rng,
		g.th,
		g.logLifetime,
		activationEpoch,
		parameter,
		chainEndsHashes,
	)
	
	root := tree.Root()
	
	pk := &PublicKey{
		Root:      root,
		Parameter: parameter,
	}
	
	sk := &SecretKey{
		PRFKey:          prfKey,
		Tree:            tree,
		Parameter:       parameter,
		ActivationEpoch: activationEpoch,
		NumActiveEpochs: numActiveEpochs,
	}
	
	return pk, sk
}

// Sign creates a signature for a message at a specific epoch
func (g *GeneralizedXMSS) Sign(rng io.Reader, sk *SecretKey, epoch uint32, message []byte) (*Signature, error) {
	// Check epoch is in activation range
	if int(epoch) < sk.ActivationEpoch || int(epoch) >= sk.ActivationEpoch+sk.NumActiveEpochs {
		return nil, errors.New("key not active during this epoch")
	}
	
	// Get Merkle path for this epoch
	path := sk.Tree.Path(epoch)
	
	// Try to encode message
	maxTries := g.encoding.MaxTries()
	var codeword encoding.Codeword
	var rho []byte
	
	for attempts := 0; attempts < maxTries; attempts++ {
		// Generate randomness
		rho = g.encoding.RandRandomness(rng)
		
		// Try to encode
		var err error
		codeword, err = g.encoding.Encode(sk.Parameter, message, rho, epoch)
		if err == nil {
			// Success
			break
		}
		
		if attempts == maxTries-1 {
			return nil, &SigningError{
				Message:  "failed to encode message",
				Attempts: maxTries,
			}
		}
	}
	
	// Compute hash values for each chain based on codeword
	numChains := g.encoding.Dimension()
	hashes := make([]th.Domain, numChains)
	
	// Parallel computation for many chains
	if numChains > 20 {
		var wg sync.WaitGroup
		wg.Add(numChains)
		
		for i := 0; i < numChains; i++ {
			go func(chainIndex int) {
				defer wg.Done()
				// Get chain start from PRF
				start := g.prf.Apply(sk.PRFKey, epoch, uint64(chainIndex))
				// Walk chain for steps determined by codeword
				steps := int(codeword[chainIndex])
				hashes[chainIndex] = th.Chain(
					g.th,
					sk.Parameter,
					epoch,
					uint8(chainIndex),
					0,
					steps,
					start,
				)
			}(i)
		}
		wg.Wait()
	} else {
		// Sequential for small number of chains
		for chainIndex := 0; chainIndex < numChains; chainIndex++ {
			start := g.prf.Apply(sk.PRFKey, epoch, uint64(chainIndex))
			steps := int(codeword[chainIndex])
			hashes[chainIndex] = th.Chain(
				g.th,
				sk.Parameter,
				epoch,
				uint8(chainIndex),
				0,
				steps,
				start,
			)
		}
	}
	
	return &Signature{
		Path:   path,
		Rho:    rho,
		Hashes: hashes,
	}, nil
}

// Verify verifies a signature
func (g *GeneralizedXMSS) Verify(pk *PublicKey, epoch uint32, message []byte, sig *Signature) bool {
	if uint64(epoch) >= g.Lifetime() {
		return false
	}
	
	// Recompute codeword from message and randomness
	codeword, err := g.encoding.Encode(pk.Parameter, message, sig.Rho, epoch)
	if err != nil {
		return false
	}
	
	// Recompute public keys from signature
	chainLength := g.encoding.Base()
	numChains := g.encoding.Dimension()
	
	if len(codeword) != numChains {
		return false
	}
	
	chainEnds := make([]th.Domain, numChains)
	for chainIndex := 0; chainIndex < numChains; chainIndex++ {
		xi := codeword[chainIndex]
		// Verifier walks from xi to chain end
		steps := chainLength - 1 - int(xi)
		chainEnds[chainIndex] = th.Chain(
			g.th,
			pk.Parameter,
			epoch,
			uint8(chainIndex),
			uint8(xi),
			steps,
			sig.Hashes[chainIndex],
		)
	}
	
	// Verify Merkle path
	return merkle.VerifyPath(
		g.th,
		pk.Parameter,
		pk.Root,
		epoch,
		chainEnds,
		sig.Path,
	)
}