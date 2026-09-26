package scan

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// randomToken returns a short, unpredictable string used as a reflection
// marker so test payloads cannot collide with normal page content.
func randomToken(bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is fatal for payload uniqueness; a fixed
		// fallback keeps the scanner usable rather than crashing.
		return strings.Repeat("0", bytes*2)
	}
	return hex.EncodeToString(b)
}

// relativeDelta returns |a-b| / max(a,b) as a fraction between 0 and 1.
func relativeDelta(a, b int) float64 {
	if a < 0 {
		a = -a
	}
	if b < 0 {
		b = -b
	}
	max := a
	if b > max {
		max = b
	}
	if max == 0 {
		return 0
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	return float64(d) / float64(max)
}
