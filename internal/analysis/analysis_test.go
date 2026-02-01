package analysis

import (
	"math"
	"testing"
)

func TestAnalyzeText(t *testing.T) {
	text := "The quick brown fox jumps over the lazy dog. It was a bright cold day in April, and the clocks were striking thirteen."
	stats := AnalyzeText(text)

	if stats.CharCount == 0 {
		t.Error("CharCount should not be 0")
	}
	if stats.WordCount == 0 {
		t.Error("WordCount should not be 0")
	}
	if stats.SentenceCount != 2 {
		t.Errorf("Expected 2 sentences, got %d", stats.SentenceCount)
	}

	// Calculate expected entropy for a simple case
	// "A B A B" -> P(A)=0.5, P(B)=0.5 -> Entropy = 1.0
	simpleText := "A B A B"
	simpleStats := AnalyzeText(simpleText)
	if math.Abs(simpleStats.WordEntropy-1.0) > 0.001 {
		t.Errorf("Expected word entropy ~1.0, got %f", simpleStats.WordEntropy)
	}
}

func TestNaturalnessScore(t *testing.T) {
	naturalText := "This is a perfectly normal sentence that you might find in a conversation. It has punctuation, capitalization, and varied vocabulary."
	rubbishText := "asdf qwer zxcv poiuy lkjh mnbvc xz aq sw de fr gt hy ju ki lo"
	repetitiveText := "test test test test test test test test test test"

	naturalScore := NaturalnessScore(AnalyzeText(naturalText))
	rubbishScore := NaturalnessScore(AnalyzeText(rubbishText))
	repetitiveScore := NaturalnessScore(AnalyzeText(repetitiveText))

	if naturalScore < rubbishScore {
		t.Errorf("Natural text should score higher than rubbish. Natural: %f, Rubbish: %f", naturalScore, rubbishScore)
	}

	if naturalScore < repetitiveScore {
		t.Errorf("Natural text should score higher than repetitive text. Natural: %f, Repetitive: %f", naturalScore, repetitiveScore)
	}
}

func TestCompareToEnglish(t *testing.T) {
	englishText := "The most common letter in the English language is e. This text should have a distribution similar to standard English."
	weirdText := "zzzz qqqq xxxx jjjj"

	englishScore := CompareToEnglish(AnalyzeText(englishText))
	weirdScore := CompareToEnglish(AnalyzeText(weirdText))

	if englishScore < weirdScore {
		t.Errorf("English text should score higher than weird text. English: %f, Weird: %f", englishScore, weirdScore)
	}
}

func TestDetectionRisk(t *testing.T) {
	// Good cover text
	goodCover := "Hey, are we still on for the movies tonight? I was thinking we could grab dinner beforehand at that new Italian place."

	// Bad cover text (simulated artificial)
	badCover := "Output generated process complete. System status normal. Transmission end. x837492"

	goodRisk := DetectionRisk(goodCover)
	badRisk := DetectionRisk(badCover)

	if goodRisk > badRisk {
		t.Errorf("Good cover text should have lower risk than bad cover text. Good: %f, Bad: %f", goodRisk, badRisk)
	}

	if goodRisk > 0.5 {
		t.Logf("Warning: Good cover text has somewhat high risk: %f", goodRisk)
	}
}
