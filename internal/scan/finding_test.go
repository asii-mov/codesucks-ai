package scan

import "testing"

func TestFingerprint_LineShiftInvariance(t *testing.T) {
	// Same tool, rule, path, and snippet content must yield the same
	// fingerprint regardless of where the code sits, because line numbers are
	// deliberately excluded.
	a := Fingerprint(ToolSemgrep, "rule.x", "app/index.js", "  eval(req.query.x)")
	b := Fingerprint(ToolSemgrep, "rule.x", "app/index.js", "  eval(req.query.x)")
	if a != b {
		t.Fatalf("expected identical fingerprints, got %s vs %s", a, b)
	}
}

func TestFingerprint_WhitespaceCollapse(t *testing.T) {
	// Reindentation alone must not change the fingerprint.
	a := Fingerprint(ToolSemgrep, "rule.x", "app/index.js", "eval(req.query.x)")
	b := Fingerprint(ToolSemgrep, "rule.x", "app/index.js", "\t  eval(req.query.x)   ")
	if a != b {
		t.Fatalf("whitespace should not affect fingerprint: %s vs %s", a, b)
	}
}

func TestFingerprint_ContentChangeDiffers(t *testing.T) {
	// A real patch changes the content, so the fingerprint must change — this
	// is the Gate A "finding gone" signal.
	vuln := Fingerprint(ToolSemgrep, "rule.x", "app/index.js", "eval(req.query.x)")
	fixed := Fingerprint(ToolSemgrep, "rule.x", "app/index.js", "safeEval(req.query.x)")
	if vuln == fixed {
		t.Fatal("patched content must produce a different fingerprint")
	}
}

func TestFingerprint_DistinguishesByToolAndPath(t *testing.T) {
	base := Fingerprint(ToolSemgrep, "r", "a.js", "x")
	if base == Fingerprint(ToolTruffleHog, "r", "a.js", "x") {
		t.Error("different tools should differ")
	}
	if base == Fingerprint(ToolSemgrep, "r", "b.js", "x") {
		t.Error("different paths should differ")
	}
	if base == Fingerprint(ToolSemgrep, "r2", "a.js", "x") {
		t.Error("different rules should differ")
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !SeverityCritical.MoreSevereThan(SeverityHigh) {
		t.Error("critical > high")
	}
	if !SeverityHigh.MoreSevereThan(SeverityMedium) {
		t.Error("high > medium")
	}
	if SeverityLow.MoreSevereThan(SeverityMedium) {
		t.Error("low should not outrank medium")
	}
}

func TestSemgrepSeverity(t *testing.T) {
	cases := []struct {
		sev, impact, conf string
		want              Severity
	}{
		{"ERROR", "HIGH", "HIGH", SeverityCritical},
		{"ERROR", "HIGH", "LOW", SeverityHigh},
		{"ERROR", "", "", SeverityHigh},
		{"WARNING", "", "", SeverityMedium},
		{"INFO", "", "", SeverityLow},
		{"WARNING", "HIGH", "HIGH", SeverityCritical},
	}
	for _, c := range cases {
		if got := semgrepSeverity(c.sev, c.impact, c.conf); got != c.want {
			t.Errorf("semgrepSeverity(%q,%q,%q)=%s want %s", c.sev, c.impact, c.conf, got, c.want)
		}
	}
}

func TestTruffleHogSeverity(t *testing.T) {
	if truffleHogSeverity(true) != SeverityCritical {
		t.Error("verified secret should be critical")
	}
	if truffleHogSeverity(false) != SeverityHigh {
		t.Error("unverified secret should be high")
	}
}
