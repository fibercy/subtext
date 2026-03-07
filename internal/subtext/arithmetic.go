package subtext

import (
	"fmt"
	"sort"

	"github.com/cy/subtext/internal/llm"
)

// Arithmetic coding for steganography.
//
// Stego encoder (ArithEncoder) = AC decoder: reads message bits → selects tokens
// Stego decoder (ArithDecoder) = AC encoder: processes tokens → outputs message bits
//
// Key: message bits are padded with alternating 1/0 (not zeros) to prevent the
// value register from getting stuck at the midpoint during tail generation.
// The decoder recovers message + padding bits; caller uses length prefix to
// extract only the actual message.

const (
	PrecisionBits     = 32
	FullRange         = uint64(1) << PrecisionBits // 4294967296
	HalfRange         = FullRange >> 1
	QuarterRange      = FullRange >> 2
	QuantizationTotal = uint32(1) << 15 // 32768
	MinTokenWeight    = uint32(1)
	// PaddingBits is extra padding after the message to ensure all message bits
	// are pushed out of the encoder's value register into the token stream.
	// Alternating 1/0 padding prevents the value register from stalling.
	// PrecisionBits+8 gives safety margin beyond the theoretical minimum.
	PaddingBits = PrecisionBits + 8
)

// CandidateToken is a token with its quantized weight and cumulative range [CumStart, CumEnd).
type CandidateToken struct {
	Token    string
	Weight   uint32
	CumStart uint32
	CumEnd   uint32
}

// CandidateDistribution is a quantized probability distribution over tokens,
// sorted lexicographically for deterministic encoder/decoder agreement.
type CandidateDistribution struct {
	Tokens []CandidateToken
	Total  uint32
}

// logprobBucketWeight maps a logprob value to a coarse weight bucket.
// Uses floor(logprob) with wide 2.0-unit buckets to be robust against
// small logprob variations (±0.5) between encode and decode calls.
// Higher probability tokens get proportionally higher weights, favoring
// natural text while still encoding bits from all candidates.
func logprobBucketWeight(logprob float64) uint32 {
	switch {
	case logprob > -1.0:
		return 16 // very high probability — most natural
	case logprob > -3.0:
		return 8
	case logprob > -5.0:
		return 4
	default:
		return 2 // low probability — least natural but still usable
	}
}

// buildDistribution creates a CDF from LLM logprob candidates using coarse
// bucket weights. Candidates are sorted lexicographically for deterministic
// encoder/decoder agreement. Each candidate's weight is determined by its
// logprob bucket — higher probability tokens get higher weights, making them
// more likely to be selected. The coarse buckets (2.0-unit width) ensure
// robustness against small logprob variations between encode and decode.
func buildDistribution(candidates []llm.LogprobToken) *CandidateDistribution {
	if len(candidates) == 0 {
		return &CandidateDistribution{Total: 0}
	}

	sorted := make([]llm.LogprobToken, len(candidates))
	copy(sorted, candidates)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Token < sorted[j].Token
	})

	tokens := make([]CandidateToken, len(sorted))
	var cumulative uint32
	for i, c := range sorted {
		w := logprobBucketWeight(c.Logprob)
		tokens[i] = CandidateToken{
			Token:    c.Token,
			Weight:   w,
			CumStart: cumulative,
			CumEnd:   cumulative + w,
		}
		cumulative += w
	}

	return &CandidateDistribution{
		Tokens: tokens,
		Total:  cumulative,
	}
}

// --- Stego Encoder (= AC Decoder): message bits → tokens ---

// ArithEncoder converts message bits into token selections using arithmetic decoding.
type ArithEncoder struct {
	low    uint64
	high   uint64
	value  uint64
	bits   []bool
	bitIdx int
}

// NewArithEncoder initializes the encoder with the message bits to hide.
// Bits are padded with alternating 1/0 to prevent the value register from
// getting stuck at the midpoint (0x80000000) during tail generation.
func NewArithEncoder(messageBits []bool) *ArithEncoder {
	padded := make([]bool, len(messageBits)+PaddingBits)
	copy(padded, messageBits)
	// Alternating padding: 1,0,1,0,... prevents fixed-point at HalfRange
	for i := len(messageBits); i < len(padded); i++ {
		padded[i] = (i & 1) == 1
	}

	var value uint64
	for i := 0; i < PrecisionBits; i++ {
		value <<= 1
		if i < len(padded) && padded[i] {
			value |= 1
		}
	}

	return &ArithEncoder{
		low:    0,
		high:   FullRange - 1,
		value:  value,
		bits:   padded,
		bitIdx: PrecisionBits,
	}
}

// Done returns true when all original message bits AND padding have been consumed,
// meaning the message is fully encoded in the token stream.
func (e *ArithEncoder) Done(originalBitLen int) bool {
	return e.bitIdx >= originalBitLen+PaddingBits
}

// BitsConsumed returns how many original message bits have been consumed.
func (e *ArithEncoder) BitsConsumed() int {
	n := e.bitIdx - PrecisionBits
	if n < 0 {
		return 0
	}
	return n
}

func (e *ArithEncoder) readBit() bool {
	if e.bitIdx < len(e.bits) {
		b := e.bits[e.bitIdx]
		e.bitIdx++
		return b
	}
	e.bitIdx++
	return false
}

// EncodeStep selects a token from dist based on the current code value.
func (e *ArithEncoder) EncodeStep(dist *CandidateDistribution) string {
	rng := e.high - e.low + 1
	total := uint64(dist.Total)

	offset := e.value - e.low
	scaled := ((offset+1)*total - 1) / rng
	if scaled >= total {
		scaled = total - 1
	}

	var selected *CandidateToken
	for i := range dist.Tokens {
		if uint64(dist.Tokens[i].CumStart) <= scaled && scaled < uint64(dist.Tokens[i].CumEnd) {
			selected = &dist.Tokens[i]
			break
		}
	}
	if selected == nil {
		selected = &dist.Tokens[len(dist.Tokens)-1]
	}

	e.high = e.low + (rng*uint64(selected.CumEnd)/total) - 1
	e.low = e.low + (rng * uint64(selected.CumStart) / total)

	e.renormalize()
	return selected.Token
}

func (e *ArithEncoder) renormalize() {
	for {
		if e.high < HalfRange {
			e.low <<= 1
			e.high = (e.high << 1) | 1
			e.value = (e.value << 1)
			if e.readBit() {
				e.value |= 1
			}
		} else if e.low >= HalfRange {
			e.low = (e.low - HalfRange) << 1
			e.high = ((e.high - HalfRange) << 1) | 1
			e.value = ((e.value - HalfRange) << 1)
			if e.readBit() {
				e.value |= 1
			}
		} else if e.low >= QuarterRange && e.high < 3*QuarterRange {
			e.low = (e.low - QuarterRange) << 1
			e.high = ((e.high - QuarterRange) << 1) | 1
			e.value = ((e.value - QuarterRange) << 1)
			if e.readBit() {
				e.value |= 1
			}
		} else {
			break
		}
	}
}

// --- Stego Decoder (= AC Encoder): tokens → message bits ---

// ArithDecoder recovers message bits from observed tokens using arithmetic encoding.
type ArithDecoder struct {
	low     uint64
	high    uint64
	pending int
	bits    []bool
}

// NewArithDecoder initializes the decoder.
func NewArithDecoder() *ArithDecoder {
	return &ArithDecoder{
		low:  0,
		high: FullRange - 1,
	}
}

func (d *ArithDecoder) outputBit(bit bool) {
	d.bits = append(d.bits, bit)
	opposite := !bit
	for ; d.pending > 0; d.pending-- {
		d.bits = append(d.bits, opposite)
	}
}

// DecodeStep processes an observed token, narrows the interval, and recovers bits.
func (d *ArithDecoder) DecodeStep(dist *CandidateDistribution, token string) error {
	var found *CandidateToken
	for i := range dist.Tokens {
		if dist.Tokens[i].Token == token {
			found = &dist.Tokens[i]
			break
		}
	}
	if found == nil {
		return fmt.Errorf("token %q not in distribution", token)
	}

	rng := d.high - d.low + 1
	total := uint64(dist.Total)

	d.high = d.low + (rng*uint64(found.CumEnd)/total) - 1
	d.low = d.low + (rng * uint64(found.CumStart) / total)

	for {
		if d.high < HalfRange {
			d.outputBit(false)
			d.low <<= 1
			d.high = (d.high << 1) | 1
		} else if d.low >= HalfRange {
			d.outputBit(true)
			d.low = (d.low - HalfRange) << 1
			d.high = ((d.high - HalfRange) << 1) | 1
		} else if d.low >= QuarterRange && d.high < 3*QuarterRange {
			d.pending++
			d.low = (d.low - QuarterRange) << 1
			d.high = ((d.high - QuarterRange) << 1) | 1
		} else {
			break
		}
	}

	return nil
}

// Flush outputs the final bits needed to complete the bitstream.
func (d *ArithDecoder) Flush() {
	d.pending++
	if d.low < QuarterRange {
		d.outputBit(false)
	} else {
		d.outputBit(true)
	}
}

// BitsRecovered returns the total number of bits recovered so far.
func (d *ArithDecoder) BitsRecovered() int {
	return len(d.bits)
}

// Bits returns all recovered bits.
func (d *ArithDecoder) Bits() []bool {
	return d.bits
}
