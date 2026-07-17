package scan

import (
	"sort"
	"strings"
	"sync"
)

// redactedMarker replaces any raw secret value wherever it might otherwise be
// printed.
const redactedMarker = "***REDACTED***"

// Redactor holds the set of raw secret values discovered during scanning and
// scrubs them from any string before it reaches a log, PR body, or report. It
// is safe for concurrent use.
type Redactor struct {
	mu     sync.RWMutex
	values map[string]struct{}
}

// NewRedactor returns an empty Redactor.
func NewRedactor() *Redactor {
	return &Redactor{values: make(map[string]struct{})}
}

// Add records a raw secret value to be scrubbed. Empty and whitespace-only
// values are ignored. The caller should discard the raw value after adding it.
func (r *Redactor) Add(raw string) {
	if strings.TrimSpace(raw) == "" {
		return
	}
	r.mu.Lock()
	r.values[raw] = struct{}{}
	r.mu.Unlock()
}

// Redact replaces every recorded secret value in s with a fixed marker. Longer
// values are replaced first so that a secret that contains another as a
// substring is fully masked.
func (r *Redactor) Redact(s string) string {
	r.mu.RLock()
	vals := make([]string, 0, len(r.values))
	for v := range r.values {
		vals = append(vals, v)
	}
	r.mu.RUnlock()

	sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
	for _, v := range vals {
		s = strings.ReplaceAll(s, v, redactedMarker)
	}
	return s
}

// mask returns a display-safe rendering of a raw secret: the first and last few
// characters with the middle elided. Used only when a scanner gives us no
// pre-redacted form.
func mask(raw string) string {
	const keep = 4
	if len(raw) <= keep*2 {
		return redactedMarker
	}
	return raw[:keep] + "…" + raw[len(raw)-keep:]
}
