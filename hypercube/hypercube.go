// Package hypercube implements hypercube layer calculations for Target-Sum encoding
package hypercube

import (
	"math/big"
	"sync"
)

// maxDimension is the maximum dimension precomputed for layer sizes
const maxDimension = 100

// LayerInfo holds the sizes of each layer and their cumulative sums
type LayerInfo struct {
	sizes       []*big.Int // Number of vertices in each layer d
	prefixSums  []*big.Int // Cumulative number of vertices up to layer d
}

// NewLayerInfo creates layer info for given base w and dimension v
func NewLayerInfo(w, v int) *LayerInfo {
	// In a hypercube {0, ..., w-1}^v, layers are defined by the sum of coordinates
	// Layer d contains all vertices where sum of coordinates = (w-1)*v - d
	// So layer 0 has sum = (w-1)*v, layer (w-1)*v has sum = 0
	// Maximum layer index is (w-1)*v
	
	maxLayer := v * (w - 1)
	info := &LayerInfo{
		sizes:      make([]*big.Int, maxLayer+1),
		prefixSums: make([]*big.Int, maxLayer+1),
	}
	
	// Calculate size of each layer using dynamic programming
	// dp[layer][positions] = number of ways to achieve sum=(w-1)*v-layer using 'positions' coordinates
	
	for layer := 0; layer <= maxLayer; layer++ {
		targetSum := (w-1)*v - layer
		
		if targetSum < 0 {
			info.sizes[layer] = big.NewInt(0)
		} else if targetSum == 0 {
			// Only one way: all zeros
			info.sizes[layer] = big.NewInt(1)
		} else if targetSum == (w-1)*v {
			// Only one way: all (w-1)s
			info.sizes[layer] = big.NewInt(1)
		} else {
			// Count vertices with given sum using stars and bars
			// This is the number of ways to write targetSum as sum of v non-negative integers,
			// each at most w-1
			info.sizes[layer] = countVerticesWithSum(w, v, targetSum)
		}
		
		// Calculate prefix sum
		if layer == 0 {
			info.prefixSums[layer] = new(big.Int).Set(info.sizes[layer])
		} else {
			info.prefixSums[layer] = new(big.Int).Add(info.prefixSums[layer-1], info.sizes[layer])
		}
	}
	
	return info
}

// countVerticesWithSum counts vertices in {0,...,w-1}^v with coordinate sum = s
func countVerticesWithSum(w, v, s int) *big.Int {
	// Use inclusion-exclusion to count solutions to:
	// x1 + x2 + ... + xv = s, where 0 <= xi < w
	
	if s < 0 || s > (w-1)*v {
		return big.NewInt(0)
	}
	
	result := big.NewInt(0)
	
	// Stars and bars with upper bounds using inclusion-exclusion
	for k := 0; k <= v; k++ {
		if s-k*w < 0 {
			break
		}
		
		// C(v, k) * C(s - k*w + v - 1, v - 1)
		term := binomial(v, k)
		term2 := binomial(s-k*w+v-1, v-1)
		term.Mul(term, term2)
		
		if k%2 == 0 {
			result.Add(result, term)
		} else {
			result.Sub(result, term)
		}
	}
	
	return result
}

// SizesSumInRange returns the sum of sizes in the inclusive range [start, end]
func (info *LayerInfo) SizesSumInRange(start, end int) *big.Int {
	if start == 0 {
		return new(big.Int).Set(info.prefixSums[end])
	}
	return new(big.Int).Sub(info.prefixSums[end], info.prefixSums[start-1])
}

// Cache for layer info, indexed by base w
var layerCache = struct {
	sync.RWMutex
	data map[int]map[int]*LayerInfo // map[base]map[dimension]*LayerInfo
}{
	data: make(map[int]map[int]*LayerInfo),
}

// GetLayerInfo returns cached layer info for given base and dimension
func GetLayerInfo(w, v int) *LayerInfo {
	layerCache.RLock()
	if baseMap, ok := layerCache.data[w]; ok {
		if info, ok := baseMap[v]; ok {
			layerCache.RUnlock()
			return info
		}
	}
	layerCache.RUnlock()
	
	// Need to create and cache
	layerCache.Lock()
	defer layerCache.Unlock()
	
	// Double-check after acquiring write lock
	if baseMap, ok := layerCache.data[w]; ok {
		if info, ok := baseMap[v]; ok {
			return info
		}
	}
	
	// Create new layer info
	info := NewLayerInfo(w, v)
	
	// Store in cache
	if layerCache.data[w] == nil {
		layerCache.data[w] = make(map[int]*LayerInfo)
	}
	layerCache.data[w][v] = info
	
	return info
}

// CountVerticesTargetSum counts vertices with target sum in given layer range
func CountVerticesTargetSum(w, v, s, minLayer, maxLayer int) *big.Int {
	if s < 0 || minLayer > maxLayer || minLayer < 0 || maxLayer > v {
		return big.NewInt(0)
	}
	
	// Use dynamic programming to count vertices
	// dp[layer][sum] = number of ways to achieve sum using exactly 'layer' coordinates
	
	dp := make(map[int]map[int]*big.Int)
	
	// Initialize: layer 0, sum 0 = 1 way (all zeros)
	dp[0] = make(map[int]*big.Int)
	dp[0][0] = big.NewInt(1)
	
	// Fill dp table
	for layer := 1; layer <= maxLayer; layer++ {
		dp[layer] = make(map[int]*big.Int)
		
		for prevSum := range dp[layer-1] {
			if prevSum > s {
				continue
			}
			
			// Try adding each possible value (1 to w-1) at this position
			for val := 1; val < w; val++ {
				newSum := prevSum + val
				if newSum <= s {
					if dp[layer][newSum] == nil {
						dp[layer][newSum] = new(big.Int)
					}
					
					// Add the number of ways from previous layer
					// multiplied by number of positions we can place this value
					ways := new(big.Int).Set(dp[layer-1][prevSum])
					
					// Number of unused positions = v - (layer-1)
					unusedPos := v - layer + 1
					ways.Mul(ways, big.NewInt(int64(unusedPos)))
					
					dp[layer][newSum].Add(dp[layer][newSum], ways)
				}
			}
		}
	}
	
	// Sum up counts for target sum s in the requested layer range
	result := new(big.Int)
	for layer := minLayer; layer <= maxLayer; layer++ {
		if count, ok := dp[layer][s]; ok {
			result.Add(result, count)
		}
	}
	
	return result
}

// binomial calculates the binomial coefficient "n choose k"
func binomial(n, k int) *big.Int {
	if k > n || k < 0 {
		return big.NewInt(0)
	}
	if k == 0 || k == n {
		return big.NewInt(1)
	}
	
	// Use the formula: C(n,k) = n! / (k! * (n-k)!)
	// But calculate it more efficiently as: C(n,k) = n*(n-1)*...*(n-k+1) / k!
	
	result := big.NewInt(1)
	for i := 0; i < k; i++ {
		result.Mul(result, big.NewInt(int64(n-i)))
		result.Div(result, big.NewInt(int64(i+1)))
	}
	
	return result
}

// ComputeIndexBounds computes the bounds for vertex indices in a hypercube layer
func ComputeIndexBounds(w, v, s, minLayer, maxLayer int) (*big.Int, *big.Int) {
	info := GetLayerInfo(w, v)
	
	// Lower bound: sum of vertices in layers before minLayer
	lowerBound := new(big.Int)
	if minLayer > 0 {
		lowerBound = info.SizesSumInRange(0, minLayer-1)
	}
	
	// Upper bound: sum of vertices up to and including maxLayer
	upperBound := info.SizesSumInRange(0, maxLayer)
	
	return lowerBound, upperBound
}