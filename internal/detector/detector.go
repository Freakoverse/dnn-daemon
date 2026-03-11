// Package detector provides DNN name detection using the same patterns as the Min browser.
//
// DNN addresses are detected by pattern, not by a fixed TLD like .com.
// This allows them to coexist with traditional DNS without collisions.
package detector

import (
	"strings"
)

// IsDNNName checks if a domain name is a DNN address.
// Detects ENCODED format: n + BIP39word1 + BIP39word2 + [cycleDigits] + positionLetters(a-z, 1+)
//
// Uses greedy prefix matching to mirror the node encoder's Decode() logic.
//
// Examples:
//   - nabandonaread      → YES (n + abandon + area + d)
//   - freakoverse.nabandonaread → YES (subdomain of DNN)
//   - nabceabsurd        → YES (n + ... greedy match)
//   - google.com         → NO (TLD "com" < 8 chars)
//   - netflix.com        → NO (TLD "com" < 8 chars)
//
// Performance: 99.9% of queries exit immediately via TLD length check.
func IsDNNName(name string) bool {
	if name == "" || len(name) < 8 {
		return false
	}

	// Spaces mean it's a search query, not a domain
	if strings.Contains(name, " ") {
		return false
	}

	// Remove trailing dot if present (FQDN format) and lowercase
	name = strings.TrimSuffix(name, ".")
	name = strings.ToLower(name)

	// Split by dots to get TLD
	parts := strings.Split(name, ".")
	tld := parts[len(parts)-1]

	// ULTRA-FAST EXIT: DNN encoded format requires TLD >= 8 chars
	// This eliminates 99.9% of queries (.com, .org, .net, .io = all < 8)
	if len(tld) < 8 {
		return false
	}

	// TLD must start with 'n' for encoded format
	if tld[0] != 'n' {
		return false
	}

	return isDNNEncoded(tld)
}

// GetTLD returns the DNN "TLD" part of a domain.
// For "freakoverse.nabobabout", returns "nabobabout"
// For "nabobabout.nabceabsurd", returns "nabobabout" (leftmost DNN ID)
// For "nabceabsurd", returns "nabceabsurd"
func GetTLD(name string) string {
	name = strings.TrimSuffix(name, ".")
	name = strings.ToLower(name)
	parts := strings.Split(name, ".")

	// Check each part from the LEFT to find the first valid DNN ID
	for _, part := range parts {
		if isSinglePartDNN(part) {
			return part
		}
	}

	// Fallback: return the last part (TLD position)
	return parts[len(parts)-1]
}

// isSinglePartDNN checks if a single part (no dots) is a valid DNN ID
func isSinglePartDNN(part string) bool {
	if len(part) < 8 {
		return false
	}
	if part[0] != 'n' {
		return false
	}
	return isDNNEncoded(part)
}

// isDNNEncoded checks if a string matches the DNN encoded format:
// n + BIP39word1 + BIP39word2 + [cycleDigits] + positionLetters(a-z, 1+)
//
// Uses greedy prefix matching (longest BIP39 word first) to mirror the
// node encoder's Decode() logic.
func isDNNEncoded(s string) bool {
	// Strip 'n' prefix
	rest := s[1:]

	// Greedy match BIP39 word1 from start
	word1, remainder := matchBIP39Prefix(rest)
	if word1 == "" {
		return false
	}

	// Greedy match BIP39 word2 from remainder
	word2, remainder := matchBIP39Prefix(remainder)
	if word2 == "" {
		return false
	}

	// Skip optional cycle digits (0-9)
	for len(remainder) > 0 && remainder[0] >= '0' && remainder[0] <= '9' {
		remainder = remainder[1:]
	}

	// Must have at least one position letter (a-z) remaining
	if len(remainder) == 0 {
		return false
	}

	// All remaining characters must be lowercase letters (position encoding)
	for _, c := range remainder {
		if c < 'a' || c > 'z' {
			return false
		}
	}

	return true
}

// matchBIP39Prefix finds the longest BIP39 word that matches at the start of s.
// Returns the matched word and the remaining string, or ("", s) if no match.
func matchBIP39Prefix(s string) (string, string) {
	if s == "" {
		return "", s
	}

	bestMatch := ""
	// BIP39 words are 3-8 chars long
	for wordLen := 8; wordLen >= 3; wordLen-- {
		if wordLen > len(s) {
			continue
		}
		candidate := s[:wordLen]
		if BIP39Words[candidate] {
			if len(candidate) > len(bestMatch) {
				bestMatch = candidate
			}
		}
	}

	if bestMatch == "" {
		return "", s
	}

	return bestMatch, s[len(bestMatch):]
}
