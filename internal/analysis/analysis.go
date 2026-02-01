// Package analysis provides statistical analysis tools for steganography detection resistance.
package analysis

import (
	"math"
	"strings"
	"unicode"
)

// TextStats contains statistical metrics about text
type TextStats struct {
	// Basic counts
	CharCount      int
	WordCount      int
	SentenceCount  int
	ParagraphCount int

	// Character distribution
	LetterFreq    map[rune]float64
	AvgWordLength float64

	// Entropy metrics
	CharEntropy float64
	WordEntropy float64

	// Naturalness indicators
	PunctuationRatio    float64
	CapitalizationRatio float64
	RepetitionScore     float64
}

// AnalyzeText computes statistical metrics for the given text
func AnalyzeText(text string) *TextStats {
	stats := &TextStats{
		LetterFreq: make(map[rune]float64),
	}

	if len(text) == 0 {
		return stats
	}

	// Count characters
	stats.CharCount = len(text)

	// Count words
	words := strings.Fields(text)
	stats.WordCount = len(words)

	// Count sentences (rough approximation)
	for _, r := range text {
		if r == '.' || r == '!' || r == '?' {
			stats.SentenceCount++
		}
	}
	if stats.SentenceCount == 0 && stats.WordCount > 0 {
		stats.SentenceCount = 1
	}

	// Count paragraphs
	stats.ParagraphCount = strings.Count(text, "\n\n") + 1

	// Calculate letter frequencies and other metrics
	letterCount := 0
	punctCount := 0
	upperCount := 0
	for _, r := range text {
		if unicode.IsLetter(r) {
			letterCount++
			lower := unicode.ToLower(r)
			stats.LetterFreq[lower]++
			if unicode.IsUpper(r) {
				upperCount++
			}
		} else if unicode.IsPunct(r) {
			punctCount++
		}
	}

	// Normalize frequencies
	for r := range stats.LetterFreq {
		stats.LetterFreq[r] /= float64(letterCount)
	}

	// Calculate average word length
	totalWordLen := 0
	for _, word := range words {
		totalWordLen += len(word)
	}
	if stats.WordCount > 0 {
		stats.AvgWordLength = float64(totalWordLen) / float64(stats.WordCount)
	}

	// Calculate ratios
	if stats.CharCount > 0 {
		stats.PunctuationRatio = float64(punctCount) / float64(stats.CharCount)
	}
	if letterCount > 0 {
		stats.CapitalizationRatio = float64(upperCount) / float64(letterCount)
	}

	// Calculate character entropy
	stats.CharEntropy = calculateEntropy(stats.LetterFreq)

	// Calculate word frequency and entropy
	wordFreq := make(map[string]float64)
	for _, word := range words {
		wordFreq[strings.ToLower(word)]++
	}
	for w := range wordFreq {
		wordFreq[w] /= float64(stats.WordCount)
	}
	stats.WordEntropy = calculateEntropy(wordFreq)

	// Calculate repetition score (lower is more natural)
	stats.RepetitionScore = calculateRepetitionScore(words)

	return stats
}

// calculateEntropy computes Shannon entropy from a frequency distribution
func calculateEntropy[K comparable](freq map[K]float64) float64 {
	var entropy float64
	for _, p := range freq {
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// calculateRepetitionScore measures how repetitive the text is
func calculateRepetitionScore(words []string) float64 {
	if len(words) < 2 {
		return 0
	}

	// Count consecutive same or similar words
	repeatCount := 0
	for i := 1; i < len(words); i++ {
		if strings.EqualFold(words[i], words[i-1]) {
			repeatCount++
		}
	}

	// Count overall word repetition
	wordCounts := make(map[string]int)
	for _, w := range words {
		wordCounts[strings.ToLower(w)]++
	}

	maxRepeat := 0
	for _, count := range wordCounts {
		if count > maxRepeat {
			maxRepeat = count
		}
	}

	// Combine metrics
	score := float64(repeatCount) / float64(len(words)-1)
	if len(words) > 0 {
		score += float64(maxRepeat) / float64(len(words)) * 0.5
	}

	return score
}

// NaturalnessScore returns a 0-1 score of how natural the text appears
// Higher scores indicate more natural-looking text
func NaturalnessScore(stats *TextStats) float64 {
	if stats.WordCount == 0 {
		return 0
	}

	score := 1.0

	// Check average word length (English averages ~4.5 chars)
	avgWordPenalty := math.Abs(stats.AvgWordLength-4.5) / 10.0
	score -= avgWordPenalty

	// Check character entropy (English text ~4.0-4.5 bits)
	if stats.CharEntropy < 3.5 || stats.CharEntropy > 5.0 {
		score -= 0.2
	}

	// Check punctuation ratio (typically 5-15%)
	if stats.PunctuationRatio < 0.02 || stats.PunctuationRatio > 0.20 {
		score -= 0.1
	}

	// Check capitalization (typically ~3-8% for normal text)
	if stats.CapitalizationRatio < 0.01 || stats.CapitalizationRatio > 0.15 {
		score -= 0.1
	}

	// Check repetition
	if stats.RepetitionScore > 0.1 {
		score -= stats.RepetitionScore
	}

	// Clamp to [0, 1]
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return score
}

// CompareToEnglish compares letter frequencies to standard English
func CompareToEnglish(stats *TextStats) float64 {
	// Standard English letter frequencies
	englishFreq := map[rune]float64{
		'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070,
		'n': 0.067, 's': 0.063, 'h': 0.061, 'r': 0.060, 'd': 0.043,
		'l': 0.040, 'c': 0.028, 'u': 0.028, 'm': 0.024, 'w': 0.024,
		'f': 0.022, 'g': 0.020, 'y': 0.020, 'p': 0.019, 'b': 0.015,
		'v': 0.010, 'k': 0.008, 'j': 0.002, 'x': 0.002, 'q': 0.001,
		'z': 0.001,
	}

	// Calculate chi-squared distance
	var chiSquared float64
	for letter, expected := range englishFreq {
		observed := stats.LetterFreq[letter]
		if expected > 0 {
			diff := observed - expected
			chiSquared += (diff * diff) / expected
		}
	}

	// Convert to similarity score (1 = perfect match, 0 = very different)
	// chiSquared near 0 is good, higher values indicate deviation
	similarity := math.Exp(-chiSquared * 5)
	return similarity
}

// DetectionRisk estimates the risk of steganographic detection
// Returns a value from 0 (low risk) to 1 (high risk)
func DetectionRisk(text string) float64 {
	stats := AnalyzeText(text)

	// Calculate various risk factors
	naturalness := NaturalnessScore(stats)
	englishSimilarity := CompareToEnglish(stats)

	// Weight factors
	risk := 1.0 - (naturalness*0.5 + englishSimilarity*0.5)

	// Additional checks
	if stats.WordCount < 10 {
		risk += 0.1 // Very short messages are suspicious
	}

	if stats.RepetitionScore > 0.2 {
		risk += 0.2 // High repetition is unnatural
	}

	// Clamp
	if risk < 0 {
		risk = 0
	}
	if risk > 1 {
		risk = 1
	}

	return risk
}
