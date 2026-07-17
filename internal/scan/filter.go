package scan

import (
	"path/filepath"
	"sort"
	"strings"
)

// skipDirs are path prefixes for vendored, dependency, and build-output trees
// that we never patch.
var skipDirs = []string{"node_modules/", "vendor/", "dist/", "build/"}

// skipSuffixes are filename patterns for minified and generated files.
var skipSuffixes = []string{".min.js", "_pb.go", ".generated.go", ".generated.js", ".generated.ts"}

// skipPath reports whether a finding's file should be excluded from analysis
// because it lives in vendored/build output or is generated/minified.
func skipPath(rel string) bool {
	rel = filepath.ToSlash(rel)
	for _, d := range skipDirs {
		if rel == strings.TrimSuffix(d, "/") || strings.HasPrefix(rel, d) || strings.Contains(rel, "/"+d) {
			return true
		}
	}
	base := rel
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		base = rel[i+1:]
	}
	for _, s := range skipSuffixes {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	// generic ".generated." marker in the filename
	if strings.Contains(base, ".generated.") {
		return true
	}
	return false
}

// Filter drops INFO-severity findings and findings in skipped paths, then
// deduplicates by fingerprint. The result is sorted most-severe first, ties
// broken by file then rule for deterministic ordering.
func Filter(findings []Finding) []Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity == SeverityInfo {
			continue
		}
		if skipPath(f.File) {
			continue
		}
		if _, dup := seen[f.Fingerprint]; dup {
			continue
		}
		seen[f.Fingerprint] = struct{}{}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity.MoreSevereThan(out[j].Severity)
		}
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}
