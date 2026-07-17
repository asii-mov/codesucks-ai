package scan

import (
	"os"
	"strings"
	"testing"
)

func TestParseSemgrepJSON(t *testing.T) {
	data, err := os.ReadFile("../../testdata/semgrep/basic.json")
	if err != nil {
		t.Fatal(err)
	}
	findings, err := parseSemgrepJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("expected 4 raw findings (filtering happens later), got %d", len(findings))
	}

	eval := findings[0]
	if eval.Severity != SeverityCritical {
		t.Errorf("eval finding should be CRITICAL (impact+confidence HIGH), got %s", eval.Severity)
	}
	if len(eval.CWE) != 1 || !strings.HasPrefix(eval.CWE[0], "CWE-95") {
		t.Errorf("expected CWE-95 string, got %v", eval.CWE)
	}
	if eval.StartLine != 12 {
		t.Errorf("expected start line 12, got %d", eval.StartLine)
	}
	if eval.Fingerprint == "" {
		t.Error("fingerprint must be computed when absent")
	}

	xss := findings[1]
	if xss.Fingerprint != "abc123preexisting" {
		t.Errorf("should prefer semgrep's own fingerprint, got %s", xss.Fingerprint)
	}
	if len(xss.CWE) != 1 || xss.CWE[0] != "CWE-79" {
		t.Errorf("expected CWE-79 from array, got %v", xss.CWE)
	}
	if xss.Severity != SeverityMedium {
		t.Errorf("warning without high impact/conf should be MEDIUM, got %s", xss.Severity)
	}
}

func TestParseTruffleHog(t *testing.T) {
	data, err := os.ReadFile("../../testdata/trufflehog/basic.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	red := NewRedactor()
	findings, err := parseTruffleHogNDJSON(data, red)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 secret findings (log lines skipped), got %d", len(findings))
	}

	aws := findings[0]
	if aws.Severity != SeverityCritical {
		t.Errorf("verified AWS key should be CRITICAL, got %s", aws.Severity)
	}
	if !aws.IsSecret() || aws.Secret.Detector != "AWS" {
		t.Errorf("expected AWS secret meta, got %+v", aws.Secret)
	}
	if aws.File != "config/secrets.js" || aws.StartLine != 3 {
		t.Errorf("wrong location: %s:%d", aws.File, aws.StartLine)
	}

	// Raw secret must never appear on the finding.
	for _, f := range findings {
		if strings.Contains(f.Snippet, "AKIAIOSFODNN7EXAMPLE") {
			t.Error("raw AWS key leaked into snippet")
		}
		if strings.Contains(f.Message, "sk_live_unverified") {
			t.Error("raw generic key leaked into message")
		}
	}

	// Redactor must scrub the raw values it was seeded with.
	leaky := "here is AKIAIOSFODNN7EXAMPLE and sk_live_unverified_example_key_1234567890"
	scrubbed := red.Redact(leaky)
	if strings.Contains(scrubbed, "AKIAIOSFODNN7EXAMPLE") || strings.Contains(scrubbed, "sk_live_unverified") {
		t.Errorf("redactor failed to scrub: %s", scrubbed)
	}

	// The unverified finding had no Redacted form; we must have masked it.
	gen := findings[1]
	if gen.Secret.Redacted == "" || strings.Contains(gen.Secret.Redacted, "unverified_example") {
		t.Errorf("expected masked redacted form, got %q", gen.Secret.Redacted)
	}
}
