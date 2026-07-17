package gates

import (
	"context"
	"fmt"
	"strings"

	"github.com/asii-mov/codesucks-ai/internal/scan"
)

// VerifyFix is Gate A. It re-runs the finding's scanner over the changed files
// and passes only if the original finding's fingerprint is gone AND no new
// findings were introduced relative to a pre-patch scan of those same files.
func VerifyFix(ctx context.Context, f scan.Finding, prePatchOnChanged []scan.Finding, changed []string, rescan Rescanner) (Result, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	post, err := rescan(ctx, changed)
	if err != nil {
		return Result{}, fmt.Errorf("gate A rescan: %w", err)
	}

	res := Result{
		Name:     "fix-verified",
		Command:  fmt.Sprintf("re-run %s on %d changed file(s)", f.Tool, len(changed)),
		Baseline: len(prePatchOnChanged),
		After:    len(post),
	}

	for _, p := range post {
		if p.Fingerprint == f.Fingerprint {
			res.Passed = false
			res.Detail = fmt.Sprintf("the original finding (%s) is still present after the patch", f.RuleID)
			return res, nil
		}
	}

	pre := make(map[string]struct{}, len(prePatchOnChanged))
	for _, p := range prePatchOnChanged {
		pre[p.Fingerprint] = struct{}{}
	}
	var introduced []string
	for _, p := range post {
		if _, existed := pre[p.Fingerprint]; !existed {
			introduced = append(introduced, p.RuleID)
		}
	}
	if len(introduced) > 0 {
		res.Passed = false
		res.Detail = fmt.Sprintf("the patch introduced %d new finding(s): %s", len(introduced), strings.Join(introduced, ", "))
		return res, nil
	}

	res.Passed = true
	res.Detail = "the vulnerability is gone and no new findings were introduced"
	return res, nil
}
