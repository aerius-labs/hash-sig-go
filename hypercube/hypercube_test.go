package hypercube

import (
	"math/big"
	"testing"
)

// Test basic hypercube part size calculations
func TestHypercubePartSize(t *testing.T) {
	// Test cases from Rust tests
	testCases := []struct {
		w, v, d  int
		expected string
	}{
		// Case 1: w = 2, v = 1
		{2, 1, 0, "1"},
		{2, 1, 1, "2"},
		
		// Case 2: w = 3, v = 2
		{3, 2, 0, "1"},
		{3, 2, 1, "3"},
		{3, 2, 2, "6"},
		{3, 2, 3, "8"},
		{3, 2, 4, "9"},
		
		// Case 3: w = 4, v = 1
		{4, 1, 0, "1"},
		{4, 1, 1, "2"},
		{4, 1, 2, "3"},
		{4, 1, 3, "4"},
		
		// Case 4: w = 2, v = 3
		{2, 3, 0, "1"},
		{2, 3, 1, "4"},
		{2, 3, 2, "7"},
		{2, 3, 3, "8"},
	}
	
	for _, tc := range testCases {
		result := HypercubePartSize(tc.w, tc.v, tc.d)
		expected, _ := new(big.Int).SetString(tc.expected, 10)
		if result.Cmp(expected) != 0 {
			t.Errorf("HypercubePartSize(%d, %d, %d) = %s, want %s", 
				tc.w, tc.v, tc.d, result.String(), tc.expected)
		}
	}
}

// Test find layer boundaries
func TestHypercubeFindLayer(t *testing.T) {
	w := 3
	v := 2
	
	testCases := []struct {
		x            string
		expectedD    int
		expectedRem  string
	}{
		{"0", 0, "0"},
		{"1", 1, "0"},
		{"2", 1, "1"},
		{"3", 2, "0"},
		{"5", 2, "2"},
		{"6", 3, "0"},
		{"8", 4, "0"},
	}
	
	for _, tc := range testCases {
		x, _ := new(big.Int).SetString(tc.x, 10)
		d, rem := HypercubeFindLayer(w, v, x)
		expectedRem, _ := new(big.Int).SetString(tc.expectedRem, 10)
		
		if d != tc.expectedD {
			t.Errorf("HypercubeFindLayer(%d, %d, %s): d = %d, want %d",
				w, v, tc.x, d, tc.expectedD)
		}
		if rem.Cmp(expectedRem) != 0 {
			t.Errorf("HypercubeFindLayer(%d, %d, %s): rem = %s, want %s",
				w, v, tc.x, rem.String(), tc.expectedRem)
		}
	}
}

// Test map to vertex and back
func TestMapVertexRoundtrip(t *testing.T) {
	w := 4
	v := 8
	d := 20
	
	layerInfo := GetLayerInfo(w, v)
	maxX := layerInfo.Sizes[d]
	
	// Test first few values
	for x := int64(0); x < 100 && new(big.Int).SetInt64(x).Cmp(maxX) < 0; x++ {
		xBig := big.NewInt(x)
		
		// Map to vertex
		a := MapToVertex(w, v, d, xBig)
		
		// Check that vertex has correct dimension
		if len(a) != v {
			t.Errorf("MapToVertex returned wrong dimension: %d, want %d", len(a), v)
		}
		
		// Check that vertex is in layer d
		sum := 0
		for _, ai := range a {
			sum += int(ai)
		}
		expectedD := (w-1)*v - sum
		if expectedD != d {
			t.Errorf("Vertex sum indicates layer %d, want %d", expectedD, d)
		}
		
		// Map back to integer
		y := MapToInteger(w, v, d, a)
		
		// Should get back the same value
		if y.Cmp(xBig) != 0 {
			t.Errorf("Roundtrip failed: got %s, want %d", y.String(), x)
		}
	}
}

// Test with big example from Rust
func TestBigMap(t *testing.T) {
	w := 12
	v := 40
	d := 174
	xStr := "21790506781852242898091207809690042074412"
	
	x, ok := new(big.Int).SetString(xStr, 10)
	if !ok {
		t.Fatal("Failed to parse big integer")
	}
	
	// Map to vertex
	a := MapToVertex(w, v, d, x)
	
	// Map back
	y := MapToInteger(w, v, d, a)
	
	// Should match
	if x.Cmp(y) != 0 {
		t.Errorf("Big map roundtrip failed: got %s, want %s", y.String(), xStr)
	}
	
	// Verify it's in the correct layer
	sum := 0
	for _, ai := range a {
		sum += int(ai)
	}
	expectedD := (w-1)*v - sum
	if expectedD != d {
		t.Errorf("Big map vertex in wrong layer: %d, want %d", expectedD, d)
	}
}