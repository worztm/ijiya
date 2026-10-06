// Baseline support: re-running a scan in CI should only fail on findings the
// change under review introduced, not on the backlog a team already knows
// about. A baseline is simply a previous JSON report; every finding in it is
// carried forward as "known" and suppressed from the new run.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"ijiya/internal/scan"
)

// Baseline is a set of known findings loaded from an earlier JSON report.
type Baseline struct {
	known map[string]int // fingerprint -> how many times it appeared
	total int
}

// LoadBaseline reads a JSON report previously written by `-o json` and builds
// the set of findings to suppress.
//
// A missing file is not an error: the first CI run has nothing to compare
// against yet, so the scan proceeds with an empty baseline rather than
// failing the build. Any other read or parse problem is reported, because a
// silently ignored baseline would make the gate look green when it is not.
func LoadBaseline(path string) (*Baseline, error) {
	b := &Baseline{known: map[string]int{}}
	if strings.TrimSpace(path) == "" {
		return b, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return b, nil
		}
		return nil, fmt.Errorf("reading baseline %s: %w", path, err)
	}

	var parsed Report
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("baseline %s is not a valid ijiya JSON report: %w", path, err)
	}

	for _, c := range parsed.Checks {
		for _, f := range c.Findings {
			if f.CheckID == "" {
				f.CheckID = c.ID
			}
			b.known[Fingerprint(f)]++
			b.total++
		}
	}
	return b, nil
}

// Len reports how many findings the baseline carries.
func (b *Baseline) Len() int {
	if b == nil {
		return 0
	}
	return b.total
}

// Empty reports whether there is nothing to suppress.
func (b *Baseline) Empty() bool { return b.Len() == 0 }

// Fingerprint identifies a finding across scans. It deliberately ignores the
// target host and any query string: the same weakness should still match when
// the baseline was recorded against staging.example.com and the current run
// targets a preview host, or when only a session-dependent query differs.
// Check, title and path are specific enough that unrelated findings differ.
func Fingerprint(f scan.Finding) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.ToLower(strings.TrimSpace(f.CheckID)),
		normaliseTitle(f.Title),
		normalisePath(f.URL),
	}, "\x00")))
	return hex.EncodeToString(sum[:16])
}

// normaliseTitle lower-cases and collapses whitespace so cosmetic wording
// differences do not resurrect a known finding.
func normaliseTitle(title string) string {
	return strings.Join(strings.Fields(strings.ToLower(title)), " ")
}

// normalisePath keeps only the path of a finding URL, dropping the scheme,
// host, query and fragment.
func normalisePath(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" {
		// Not a URL (or one without a path): fall back to the raw string so
		// something stable is still compared.
		return strings.TrimSpace(raw)
	}
	return strings.TrimSuffix(u.Path, "/")
}

// Suppress removes findings the baseline already knows about from every check
// result and returns how many were dropped.
//
// Suppression is applied before the report is built, so the summary, risk
// score and grade all describe the *new* findings only - which is what the
// -fail-on gate must be judged against.
func (b *Baseline) Suppress(rep *Report) int {
	if b == nil || b.total == 0 || rep == nil {
		return 0
	}
	suppressed := 0
	for ci := range rep.Checks {
		src := rep.Checks[ci].Findings
		kept := make([]scan.Finding, 0, len(src))
		for _, f := range src {
			if f.CheckID == "" {
				f.CheckID = rep.Checks[ci].ID
			}
			if n := b.known[Fingerprint(f)]; n > 0 {
				b.known[Fingerprint(f)] = n - 1
				suppressed++
				continue
			}
			kept = append(kept, f)
		}
		rep.Checks[ci].Findings = kept
	}
	if suppressed > 0 {
		rep.Summary, rep.RiskScore, rep.Grade = summarise(rep.Checks)
	}
	return suppressed
}
