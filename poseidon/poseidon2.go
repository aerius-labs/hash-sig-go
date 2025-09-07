// Package poseidon implements Poseidon2 permutation over BabyBear field using gnark-crypto
package poseidon

import (
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark-crypto/field/babybear/poseidon2"
)

// Element is a BabyBear field element
type Element = babybear.Element

// Poseidon2 wraps the gnark-crypto Poseidon2 permutation
type Poseidon2 struct {
	perm  *poseidon2.Permutation
	width int
}

// NewPoseidon2_16 creates Poseidon2 with width 16 (matching Plonky3's default_babybear_poseidon2_16)
func NewPoseidon2_16() *Poseidon2 {
	// Parameters matching Plonky3: width=16, external_rounds=8, internal_rounds=13
	// The gnark-crypto implementation uses the same parameters as Plonky3
	// based on the test vectors in plonky3_interop_test.go
	perm := poseidon2.NewPermutation(16, 8, 13)
	return &Poseidon2{
		perm:  perm,
		width: 16,
	}
}

// NewPoseidon2_24 creates Poseidon2 with width 24 (matching Plonky3's default_babybear_poseidon2_24)
func NewPoseidon2_24() *Poseidon2 {
	// Parameters matching Plonky3: width=24, external_rounds=8, internal_rounds=21
	// The gnark-crypto implementation uses the same parameters as Plonky3
	// based on the test vectors in plonky3_interop_test.go
	perm := poseidon2.NewPermutation(24, 8, 21)
	return &Poseidon2{
		perm:  perm,
		width: 24,
	}
}

// Permute applies the Poseidon2 permutation in place
func (p *Poseidon2) Permute(state []Element) {
	if len(state) != p.width {
		panic("state size mismatch")
	}
	if err := p.perm.Permutation(state); err != nil {
		panic("permutation failed: " + err.Error())
	}
}

// PermuteNew applies the Poseidon2 permutation and returns a new state
func (p *Poseidon2) PermuteNew(state []Element) []Element {
	if len(state) != p.width {
		panic("state size mismatch")
	}
	newState := make([]Element, len(state))
	copy(newState, state)
	if err := p.perm.Permutation(newState); err != nil {
		panic("permutation failed: " + err.Error())
	}
	return newState
}

// Width returns the permutation width
func (p *Poseidon2) Width() int {
	return p.width
}