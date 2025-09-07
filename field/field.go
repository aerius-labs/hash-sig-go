// Package field implements the BabyBear prime field using gnark-crypto
package field

import (
	"math/big"
	
	"github.com/consensys/gnark-crypto/field/babybear"
)

// BabyBear prime: 2^31 - 2^27 + 1 = 2013265921
const P uint64 = 2013265921

// Element represents a field element in BabyBear
type Element = babybear.Element

// NewElement creates a new field element
func NewElement(v uint64) Element {
	var e Element
	e.SetUint64(v)
	return e
}

// Zero returns the zero element
func Zero() Element {
	return babybear.NewElement(0)
}

// One returns the one element  
func One() Element {
	return babybear.NewElement(1)
}

// FromBytes creates element from bytes (little-endian)
func FromBytes(b []byte) Element {
	var e Element
	e.SetBytes(b)
	return e
}

// ToBytes converts element to bytes (little-endian)
func ToBytes(e Element) []byte {
	b := e.Bytes()
	return b[:]
}

// ToBigInt converts to big.Int
func ToBigInt(e Element) *big.Int {
	return e.BigInt(big.NewInt(0))
}