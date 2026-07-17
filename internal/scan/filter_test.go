package scan

import "testing"

func TestFilter_DropsInfoVendoredAndDedups(t *testing.T) {
	in := []Finding{
		{Fingerprint: "a", Severity: SeverityInfo, File: "app/x.js"},
		{Fingerprint: "b", Severity: SeverityHigh, File: "node_modules/left-pad/index.js"},
		{Fingerprint: "c", Severity: SeverityCritical, File: "app/x.js"},
		{Fingerprint: "c", Severity: SeverityCritical, File: "app/x.js"}, // dup fingerprint
		{Fingerprint: "d", Severity: SeverityMedium, File: "dist/bundle.min.js"},
		{Fingerprint: "e", Severity: SeverityHigh, File: "app/y.js"},
	}
	out := Filter(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 findings after filtering, got %d: %+v", len(out), out)
	}
	// Sorted most-severe first.
	if out[0].Fingerprint != "c" || out[0].Severity != SeverityCritical {
		t.Errorf("expected critical first, got %+v", out[0])
	}
	if out[1].Fingerprint != "e" {
		t.Errorf("expected high second, got %+v", out[1])
	}
}

func TestSkipPath(t *testing.T) {
	skip := []string{
		"node_modules/x/index.js",
		"vendor/foo/bar.go",
		"dist/app.js",
		"build/out.js",
		"src/app.min.js",
		"api/models_pb.go",
		"gen/schema.generated.ts",
		"a/b/node_modules/c.js",
	}
	for _, p := range skip {
		if !skipPath(p) {
			t.Errorf("expected %q to be skipped", p)
		}
	}
	keep := []string{"app/routes/index.js", "src/main.go", "lib/util.py"}
	for _, p := range keep {
		if skipPath(p) {
			t.Errorf("expected %q to be kept", p)
		}
	}
}
