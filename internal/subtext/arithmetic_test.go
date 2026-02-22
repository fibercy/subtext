package subtext

import (
	"fmt"
	"math"
	"math/rand"
	"testing"

	"github.com/cy/subtext/internal/llm"
)

func TestBuildDistribution(t *testing.T) {
	candidates := []llm.LogprobToken{
		{Token: "zoo", Logprob: math.Log(0.1)},
		{Token: "apple", Logprob: math.Log(0.5)},
		{Token: "banana", Logprob: math.Log(0.4)},
	}

	dist := buildDistribution(candidates)

	// Should be sorted lexicographically
	if dist.Tokens[0].Token != "apple" {
		t.Errorf("expected first token 'apple', got %q", dist.Tokens[0].Token)
	}
	if dist.Tokens[1].Token != "banana" {
		t.Errorf("expected second token 'banana', got %q", dist.Tokens[1].Token)
	}
	if dist.Tokens[2].Token != "zoo" {
		t.Errorf("expected third token 'zoo', got %q", dist.Tokens[2].Token)
	}

	// Total should equal QuantizationTotal
	if dist.Total != QuantizationTotal {
		t.Errorf("total %d != QuantizationTotal %d", dist.Total, QuantizationTotal)
	}

	// CDF should be contiguous
	for i, tok := range dist.Tokens {
		if i == 0 && tok.CumStart != 0 {
			t.Errorf("first token CumStart should be 0, got %d", tok.CumStart)
		}
		if i > 0 && tok.CumStart != dist.Tokens[i-1].CumEnd {
			t.Errorf("gap in CDF at token %d", i)
		}
		if tok.CumEnd <= tok.CumStart {
			t.Errorf("token %d has empty range [%d, %d)", i, tok.CumStart, tok.CumEnd)
		}
	}
	if dist.Tokens[len(dist.Tokens)-1].CumEnd != QuantizationTotal {
		t.Errorf("last CumEnd %d != QuantizationTotal %d", dist.Tokens[len(dist.Tokens)-1].CumEnd, QuantizationTotal)
	}
}

func TestBuildDistributionSingleCandidate(t *testing.T) {
	candidates := []llm.LogprobToken{
		{Token: "hello", Logprob: -0.1},
	}

	dist := buildDistribution(candidates)
	if len(dist.Tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(dist.Tokens))
	}
	if dist.Tokens[0].CumStart != 0 || dist.Tokens[0].CumEnd != QuantizationTotal {
		t.Errorf("single token should span entire range")
	}
}

func TestBuildDistributionEqualProbs(t *testing.T) {
	candidates := []llm.LogprobToken{
		{Token: "a", Logprob: -1.0},
		{Token: "b", Logprob: -1.0},
		{Token: "c", Logprob: -1.0},
		{Token: "d", Logprob: -1.0},
	}

	dist := buildDistribution(candidates)
	if dist.Total != QuantizationTotal {
		t.Errorf("total %d != %d", dist.Total, QuantizationTotal)
	}
	// Each weight should be approximately QuantizationTotal/4
	for _, tok := range dist.Tokens {
		expected := QuantizationTotal / 4
		diff := int32(tok.Weight) - int32(expected)
		if diff < -2 || diff > 2 {
			t.Errorf("token %q weight %d far from expected %d", tok.Token, tok.Weight, expected)
		}
	}
}

// TestArithmeticRoundTrip verifies that encoding and decoding produce identical bits.
func TestArithmeticRoundTrip(t *testing.T) {
	// Create a fixed set of distributions (simulating per-token LLM logprobs)
	distributions := []*CandidateDistribution{
		makeDist([]string{"the", "a", "one"}, []float64{0.6, 0.3, 0.1}),
		makeDist([]string{"cat", "dog", "bird", "fish"}, []float64{0.4, 0.3, 0.2, 0.1}),
		makeDist([]string{" is", " was", " has"}, []float64{0.5, 0.3, 0.2}),
		makeDist([]string{" happy", " nice", " good", " great", " fine"}, []float64{0.3, 0.25, 0.2, 0.15, 0.1}),
		makeDist([]string{" today", " now", " here"}, []float64{0.5, 0.3, 0.2}),
		makeDist([]string{".", "!", ","}, []float64{0.6, 0.3, 0.1}),
	}

	// Test with various message lengths
	for _, msgLen := range []int{8, 16, 24, 32, 48, 64} {
		t.Run(fmt.Sprintf("bits_%d", msgLen), func(t *testing.T) {
			// Generate random message bits
			rng := rand.New(rand.NewSource(int64(msgLen)))
			bits := make([]bool, msgLen)
			for i := range bits {
				bits[i] = rng.Intn(2) == 1
			}

			// Encode: bits → tokens
			enc := NewArithEncoder(bits)
			var tokens []string
			distIdx := 0
			for distIdx < 100 {
				dist := distributions[distIdx%len(distributions)]
				token := enc.EncodeStep(dist)
				tokens = append(tokens, token)
				distIdx++
				if enc.Done(msgLen) {
					break
				}
			}
			// Generate extra tokens to push remaining state through
			for i := 0; i < 10 && distIdx < 100; i++ {
				dist := distributions[distIdx%len(distributions)]
				token := enc.EncodeStep(dist)
				tokens = append(tokens, token)
				distIdx++
			}

			// Decode: tokens → bits
			dec := NewArithDecoder()
			for i, token := range tokens {
				dist := distributions[i%len(distributions)]
				err := dec.DecodeStep(dist, token)
				if err != nil {
					t.Fatalf("decode step %d failed: %v", i, err)
				}
			}
			dec.Flush()

			recovered := dec.Bits()
			if len(recovered) < msgLen {
				t.Fatalf("recovered %d bits, need %d", len(recovered), msgLen)
			}

			// Compare first msgLen bits
			for i := 0; i < msgLen; i++ {
				if recovered[i] != bits[i] {
					t.Errorf("bit %d: got %v, want %v", i, recovered[i], bits[i])
				}
			}
		})
	}
}

func TestArithmeticSingleCandidate(t *testing.T) {
	// Single candidate: no bits should be encoded
	dist := makeDist([]string{"only"}, []float64{1.0})

	bits := []bool{true, false, true, true, false, false, true, false}
	enc := NewArithEncoder(bits)

	// Each step should return "only" and consume 0 bits
	for i := 0; i < 5; i++ {
		token := enc.EncodeStep(dist)
		if token != "only" {
			t.Errorf("step %d: expected 'only', got %q", i, token)
		}
	}

	// No bits should have been consumed
	if enc.BitsConsumed() != 0 {
		t.Errorf("expected 0 bits consumed with single candidate, got %d", enc.BitsConsumed())
	}
}

func TestArithmeticSkewedDistribution(t *testing.T) {
	// One dominant token, one rare token
	dist := makeDist([]string{"common", "rare"}, []float64{0.99, 0.01})

	bits := make([]bool, 32)
	rng := rand.New(rand.NewSource(42))
	for i := range bits {
		bits[i] = rng.Intn(2) == 1
	}

	// Encode
	enc := NewArithEncoder(bits)
	var tokens []string
	for !enc.Done(len(bits)) && len(tokens) < 500 {
		token := enc.EncodeStep(dist)
		tokens = append(tokens, token)
	}

	// Decode
	dec := NewArithDecoder()
	for _, token := range tokens {
		if err := dec.DecodeStep(dist, token); err != nil {
			t.Fatalf("decode failed: %v", err)
		}
	}
	dec.Flush()

	recovered := dec.Bits()
	if len(recovered) < len(bits) {
		t.Fatalf("recovered %d bits, need %d", len(recovered), len(bits))
	}
	for i := 0; i < len(bits); i++ {
		if recovered[i] != bits[i] {
			t.Errorf("bit %d: got %v, want %v", i, recovered[i], bits[i])
		}
	}
}

func TestArithmeticManyDistributions(t *testing.T) {
	// Simulate realistic scenario: varying distributions per position
	rng := rand.New(rand.NewSource(99))
	bits := make([]bool, 48)
	for i := range bits {
		bits[i] = rng.Intn(2) == 1
	}

	// Generate random distributions
	var dists []*CandidateDistribution
	for i := 0; i < 50; i++ {
		n := 3 + rng.Intn(15) // 3 to 17 candidates
		tokens := make([]string, n)
		probs := make([]float64, n)
		sumP := 0.0
		for j := 0; j < n; j++ {
			tokens[j] = fmt.Sprintf("t%d_%d", i, j)
			probs[j] = rng.Float64() + 0.01
			sumP += probs[j]
		}
		for j := range probs {
			probs[j] /= sumP
		}
		dists = append(dists, makeDist(tokens, probs))
	}

	// Encode
	enc := NewArithEncoder(bits)
	var resultTokens []string
	distIdx := 0
	for !enc.Done(len(bits)) && distIdx < len(dists) {
		token := enc.EncodeStep(dists[distIdx])
		resultTokens = append(resultTokens, token)
		distIdx++
	}

	// Decode
	dec := NewArithDecoder()
	for i, token := range resultTokens {
		if err := dec.DecodeStep(dists[i], token); err != nil {
			t.Fatalf("decode step %d failed: %v", i, err)
		}
	}
	dec.Flush()

	recovered := dec.Bits()
	if len(recovered) < len(bits) {
		t.Fatalf("recovered %d bits, need %d", len(recovered), len(bits))
	}
	for i := 0; i < len(bits); i++ {
		if recovered[i] != bits[i] {
			t.Errorf("bit %d: got %v, want %v", i, recovered[i], bits[i])
		}
	}

	t.Logf("encoded %d bits in %d tokens (%.1f bits/token)", len(bits), len(resultTokens), float64(len(bits))/float64(len(resultTokens)))
}

func TestArithmeticTrace(t *testing.T) {
	distributions := []*CandidateDistribution{
		makeDist([]string{"the", "a", "one"}, []float64{0.6, 0.3, 0.1}),
		makeDist([]string{"cat", "dog", "bird", "fish"}, []float64{0.4, 0.3, 0.2, 0.1}),
		makeDist([]string{" is", " was", " has"}, []float64{0.5, 0.3, 0.2}),
		makeDist([]string{" happy", " nice", " good", " great", " fine"}, []float64{0.3, 0.25, 0.2, 0.15, 0.1}),
		makeDist([]string{" today", " now", " here"}, []float64{0.5, 0.3, 0.2}),
		makeDist([]string{".", "!", ","}, []float64{0.6, 0.3, 0.1}),
	}

	rng := rand.New(rand.NewSource(16))
	bits := make([]bool, 16)
	for i := range bits {
		bits[i] = rng.Intn(2) == 1
	}

	enc := NewArithEncoder(bits)
	var tokens []string
	for i := 0; i < 30; i++ {
		dist := distributions[i%len(distributions)]
		token := enc.EncodeStep(dist)
		tokens = append(tokens, token)
		t.Logf("enc step %2d: token=%q consumed=%d low=%x high=%x value=%x",
			i, token, enc.BitsConsumed(), enc.low, enc.high, enc.value)
	}

	dec := NewArithDecoder()
	for i, token := range tokens {
		dist := distributions[i%len(distributions)]
		prevBits := dec.BitsRecovered()
		err := dec.DecodeStep(dist, token)
		if err != nil {
			t.Fatalf("dec step %d: %v", i, err)
		}
		newBits := dec.Bits()[prevBits:]
		t.Logf("dec step %2d: token=%q recovered=%d(+%d) low=%x high=%x pending=%d newbits=%v",
			i, token, dec.BitsRecovered(), len(newBits), dec.low, dec.high, dec.pending, newBits)
	}
	dec.Flush()

	recovered := dec.Bits()
	t.Logf("original:  %v", bits)
	t.Logf("recovered: %v (len=%d)", recovered[:min(len(recovered), 20)], len(recovered))

	for i := 0; i < len(bits) && i < len(recovered); i++ {
		if recovered[i] != bits[i] {
			t.Errorf("bit %d: got %v, want %v", i, recovered[i], bits[i])
		}
	}
}

// makeDist creates a CandidateDistribution from token names and probabilities.
func makeDist(tokens []string, probs []float64) *CandidateDistribution {
	candidates := make([]llm.LogprobToken, len(tokens))
	for i, tok := range tokens {
		candidates[i] = llm.LogprobToken{
			Token:   tok,
			Logprob: math.Log(probs[i]),
		}
	}
	return buildDistribution(candidates)
}

