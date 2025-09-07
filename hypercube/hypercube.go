package hypercube

import (
	"math/big"
	"sync"
)

// MaxDimension is the maximum dimension precomputed for layer sizes
const MaxDimension = 100

// LayerInfo holds the sizes of each layer and their cumulative sums
type LayerInfo struct {
	Sizes      []*big.Int // Number of vertices in each layer d
	PrefixSums []*big.Int // Cumulative number of vertices up to and including layer d
}

// SizesSumInRange returns sum of sizes in inclusive range [start, end]
func (l *LayerInfo) SizesSumInRange(start, end int) *big.Int {
	if start == 0 {
		return new(big.Int).Set(l.PrefixSums[end])
	}
	return new(big.Int).Sub(l.PrefixSums[end], l.PrefixSums[start-1])
}

// AllLayerInfoForBase is a vector of LayerInfo, indexed by dimension v
type AllLayerInfoForBase []*LayerInfo

// Global cache for layer info (sizes and prefix sums) for each base w
var (
	allLayerInfoCache = make(map[int]AllLayerInfoForBase)
	cacheMutex        sync.RWMutex
)

// getAllLayerData returns cached layer data for given base
func getAllLayerData(w int) AllLayerInfoForBase {
	cacheMutex.RLock()
	info, exists := allLayerInfoCache[w]
	cacheMutex.RUnlock()

	if !exists {
		cacheMutex.Lock()
		// Double-check after acquiring write lock
		if info, exists = allLayerInfoCache[w]; !exists {
			info = prepareLayerInfo(w)
			allLayerInfoCache[w] = info
		}
		cacheMutex.Unlock()
	}

	return info
}

// GetLayerInfo returns cached layer info for given base and dimension
func GetLayerInfo(w, v int) *LayerInfo {
	allInfo := getAllLayerData(w)
	return allInfo[v]
}

// prepareLayerInfo computes layer sizes and prefix sums by Lemma 8 in eprint 2025/889
func prepareLayerInfo(w int) AllLayerInfoForBase {
	vMax := MaxDimension
	allInfo := make(AllLayerInfoForBase, vMax+1)

	// Initialize with empty LayerInfo
	for i := range allInfo {
		allInfo[i] = &LayerInfo{}
	}

	// Base case: dimension v = 1
	dim1Sizes := make([]*big.Int, w)
	for i := 0; i < w; i++ {
		dim1Sizes[i] = big.NewInt(1)
	}

	dim1PrefixSums := make([]*big.Int, w)
	for i := 0; i < w; i++ {
		dim1PrefixSums[i] = big.NewInt(int64(i + 1))
	}

	allInfo[1] = &LayerInfo{
		Sizes:      dim1Sizes,
		PrefixSums: dim1PrefixSums,
	}

	// Inductive step: compute for dimensions v = 2 to vMax
	for v := 2; v <= vMax; v++ {
		maxD := (w - 1) * v

		// Compute the sizes for the current dimension v
		currentSizes := make([]*big.Int, maxD+1)
		for d := 0; d <= maxD; d++ {
			aiStart := max(1, max(w-d, 1))
			aiEnd := min(w, w+(w-1)*(v-1)-d)

			// If the summation range is invalid, the layer size is zero
			if aiStart > aiEnd {
				currentSizes[d] = big.NewInt(0)
				continue
			}

			// Map the range for a_i to a range for d' in the previous dimension
			dPrimeStart := d - (w - aiStart)
			dPrimeEnd := d - (w - aiEnd)

			// Sum over the relevant slice of the previous dimension's layer sizes
			currentSizes[d] = allInfo[v-1].SizesSumInRange(dPrimeStart, dPrimeEnd)
		}

		// Compute prefix sums from the newly calculated sizes
		currentPrefixSums := make([]*big.Int, maxD+1)
		currentSum := big.NewInt(0)
		for i, size := range currentSizes {
			currentSum = new(big.Int).Add(currentSum, size)
			currentPrefixSums[i] = new(big.Int).Set(currentSum)
		}

		// Store both sizes and prefix sums
		allInfo[v] = &LayerInfo{
			Sizes:      currentSizes,
			PrefixSums: currentPrefixSums,
		}
	}

	return allInfo
}

// MapToVertex maps an integer x in [0, layer_size(v, d)) to a vertex in layer d
// of the hypercube [0, w-1]^v
func MapToVertex(w, v, d int, x *big.Int) []byte {
	xCurr := new(big.Int).Set(x)
	out := make([]byte, 0, v)
	dCurr := d

	layerData := getAllLayerData(w)

	// Assert x < layer_size(v, d)
	if xCurr.Cmp(layerData[v].Sizes[d]) >= 0 {
		panic("x is too large for the given layer")
	}

	for i := 1; i < v; i++ {
		ji := -1
		rangeStart := max(0, dCurr-(w-1)*(v-i))

		for j := rangeStart; j <= min(w-1, dCurr); j++ {
			count := layerData[v-i].Sizes[dCurr-j]

			if xCurr.Cmp(count) >= 0 {
				xCurr.Sub(xCurr, count)
			} else {
				ji = j
				break
			}
		}

		if ji < 0 || ji >= w {
			panic("ji out of bounds")
		}

		ai := w - ji - 1
		out = append(out, byte(ai))
		dCurr -= w - 1 - ai
	}

	// Final coordinate
	xCurrInt := int(xCurr.Int64())
	if xCurrInt+dCurr >= w {
		panic("final coordinate out of bounds")
	}
	out = append(out, byte(w-1-xCurrInt-dCurr))

	return out
}

// HypercubePartSize returns the total size of layers 0 to d (inclusive) in hypercube [0, w-1]^v
func HypercubePartSize(w, v, d int) *big.Int {
	layerData := getAllLayerData(w)
	return new(big.Int).Set(layerData[v].PrefixSums[d])
}

// HypercubeFindLayer finds maximal d such that the total size L_<d of layers 0 to d-1 (inclusive)
// in hypercube [0, w-1]^v is not bigger than x. Returns d and x-L_<d
func HypercubeFindLayer(w, v int, x *big.Int) (int, *big.Int) {
	layerData := getAllLayerData(w)
	prefixSums := layerData[v].PrefixSums

	// Assert x < total size (w^v)
	if x.Cmp(prefixSums[len(prefixSums)-1]) >= 0 {
		panic("x is larger than hypercube size")
	}

	// partition_point finds the index of the first element p for which p > x
	// This index is the layer d where our value x resides
	d := 0
	for d < len(prefixSums) && prefixSums[d].Cmp(x) <= 0 {
		d++
	}

	if d == 0 {
		// x is in the very first layer (d=0). The remainder is x itself
		return 0, new(big.Int).Set(x)
	}

	// The cumulative size of all layers up to d-1 is at prefixSums[d-1]
	// The remainder is x minus this cumulative size
	remainder := new(big.Int).Sub(x, prefixSums[d-1])
	return d, remainder
}

// MapToInteger maps a vertex a in layer d to its index x in [0, layer_size(v, d))
func MapToInteger(w, v, d int, a []byte) *big.Int {
	if len(a) != v {
		panic("vertex has wrong dimension")
	}

	xCurr := big.NewInt(0)
	dCurr := w - 1 - int(a[v-1])

	layerData := getAllLayerData(w)

	for i := v - 2; i >= 0; i-- {
		ji := w - 1 - int(a[i])
		dCurr += ji
		jStart := max(0, dCurr-(w-1)*(v-i-1))

		rangeSum := layerData[v-i-1].SizesSumInRange(dCurr-ji+1, dCurr-jStart)
		xCurr.Add(xCurr, rangeSum)
	}

	if dCurr != d {
		panic("vertex is not in the claimed layer")
	}

	return xCurr
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}