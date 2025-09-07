package xmss

import (
	"github.com/aerius-labs/hash-sig-go/encoding/targetsum"
	"github.com/aerius-labs/hash-sig-go/encoding/winternitz"
	"github.com/aerius-labs/hash-sig-go/internal/prf"
	"github.com/aerius-labs/hash-sig-go/th/tweak_hash"
	"github.com/aerius-labs/hash-sig-go/th/message_hash"
)

// Poseidon-based instantiations with Lifetime 2^18

// Constants for Poseidon instantiations
const (
	PoseidonLogLifetime18 = 18
	PoseidonParameterLen  = 5
	PoseidonMsgHashLenFE  = 5
	PoseidonHashLenFE     = 7
	PoseidonMsgLenFE      = 9
	PoseidonTweakLenFE    = 2
	PoseidonRandLen       = 5
	PoseidonCapacity      = 9
)

// Winternitz w=1 instantiation
const (
	PoseidonChunkSizeW1        = 1
	PoseidonBaseW1             = 2
	PoseidonNumChunksW1        = 155
	PoseidonNumChunksChecksumW1 = 8
)

// NewPoseidonWinternitzW1 creates Poseidon-based XMSS with Winternitz w=1
func NewPoseidonWinternitzW1() *GeneralizedXMSS {
	messageHash := message_hash.NewPoseidonMessageHash(
		PoseidonParameterLen,
		PoseidonRandLen,
		PoseidonMsgHashLenFE,
		PoseidonNumChunksW1,
		PoseidonBaseW1,
		PoseidonTweakLenFE,
		PoseidonMsgLenFE,
	)
	
	winternitzEnc := winternitz.NewWinternitzEncoding(
		messageHash,
		PoseidonChunkSizeW1,
		PoseidonNumChunksChecksumW1,
	)
	
	tweakHash := tweak_hash.NewPoseidonTweakHash(
		PoseidonParameterLen,
		PoseidonHashLenFE,
		PoseidonTweakLenFE,
		PoseidonCapacity,
		PoseidonNumChunksW1,
	)
	
	prfFunc := prf.NewShakePRFtoField(32, PoseidonHashLenFE)
	
	return NewGeneralizedXMSS(
		prfFunc,
		winternitzEnc,
		tweakHash,
		PoseidonLogLifetime18,
	)
}

// Winternitz w=2 instantiation
const (
	PoseidonChunkSizeW2         = 2
	PoseidonBaseW2              = 4
	PoseidonNumChunksW2         = 78
	PoseidonNumChunksChecksumW2 = 4
)

// NewPoseidonWinternitzW2 creates Poseidon-based XMSS with Winternitz w=2
func NewPoseidonWinternitzW2() *GeneralizedXMSS {
	messageHash := message_hash.NewPoseidonMessageHash(
		PoseidonParameterLen,
		PoseidonRandLen,
		PoseidonMsgHashLenFE,
		PoseidonNumChunksW2,
		PoseidonBaseW2,
		PoseidonTweakLenFE,
		PoseidonMsgLenFE,
	)
	
	winternitzEnc := winternitz.NewWinternitzEncoding(
		messageHash,
		PoseidonChunkSizeW2,
		PoseidonNumChunksChecksumW2,
	)
	
	tweakHash := tweak_hash.NewPoseidonTweakHash(
		PoseidonParameterLen,
		PoseidonHashLenFE,
		PoseidonTweakLenFE,
		PoseidonCapacity,
		PoseidonNumChunksW2,
	)
	
	prfFunc := prf.NewShakePRFtoField(32, PoseidonHashLenFE)
	
	return NewGeneralizedXMSS(
		prfFunc,
		winternitzEnc,
		tweakHash,
		PoseidonLogLifetime18,
	)
}

// Winternitz w=4 instantiation
const (
	PoseidonChunkSizeW4         = 4
	PoseidonBaseW4              = 16
	PoseidonNumChunksW4         = 39
	PoseidonNumChunksChecksumW4 = 3
)

// NewPoseidonWinternitzW4 creates Poseidon-based XMSS with Winternitz w=4
func NewPoseidonWinternitzW4() *GeneralizedXMSS {
	messageHash := message_hash.NewPoseidonMessageHash(
		PoseidonParameterLen,
		PoseidonRandLen,
		PoseidonMsgHashLenFE,
		PoseidonNumChunksW4,
		PoseidonBaseW4,
		PoseidonTweakLenFE,
		PoseidonMsgLenFE,
	)
	
	winternitzEnc := winternitz.NewWinternitzEncoding(
		messageHash,
		PoseidonChunkSizeW4,
		PoseidonNumChunksChecksumW4,
	)
	
	tweakHash := tweak_hash.NewPoseidonTweakHash(
		PoseidonParameterLen,
		PoseidonHashLenFE,
		PoseidonTweakLenFE,
		PoseidonCapacity,
		PoseidonNumChunksW4,
	)
	
	prfFunc := prf.NewShakePRFtoField(32, PoseidonHashLenFE)
	
	return NewGeneralizedXMSS(
		prfFunc,
		winternitzEnc,
		tweakHash,
		PoseidonLogLifetime18,
	)
}

// Target-Sum w=256 instantiation
const (
	PoseidonTargetSumW256      = 256
	PoseidonTargetSumDim256    = 32
	PoseidonTargetSumTarget256 = 768
	PoseidonTargetSumSlack256  = 1024
)

// NewPoseidonTargetSumW256 creates Poseidon-based XMSS with Target-Sum w=256
func NewPoseidonTargetSumW256() *GeneralizedXMSS {
	messageHash := message_hash.NewPoseidonMessageHash(
		PoseidonParameterLen,
		PoseidonRandLen,
		PoseidonMsgHashLenFE,
		PoseidonTargetSumDim256,
		PoseidonTargetSumW256,
		PoseidonTweakLenFE,
		PoseidonMsgLenFE,
	)
	
	targetSumEnc := targetsum.NewTargetSumEncoding(
		messageHash,
		PoseidonTargetSumTarget256, // Just the target sum value
	)
	
	tweakHash := tweak_hash.NewPoseidonTweakHash(
		PoseidonParameterLen,
		PoseidonHashLenFE,
		PoseidonTweakLenFE,
		PoseidonCapacity,
		PoseidonTargetSumDim256,
	)
	
	prfFunc := prf.NewShakePRFtoField(32, PoseidonHashLenFE)
	
	return NewGeneralizedXMSS(
		prfFunc,
		targetSumEnc,
		tweakHash,
		PoseidonLogLifetime18,
	)
}