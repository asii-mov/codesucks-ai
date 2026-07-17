package pipeline

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/asii-mov/codesucks-ai/internal/agent"
	"github.com/asii-mov/codesucks-ai/internal/gates"
	"github.com/asii-mov/codesucks-ai/internal/repo"
	"github.com/asii-mov/codesucks-ai/internal/scan"
	"golang.org/x/sync/errgroup"
)

// Run executes the full pipeline and returns the run report. It never returns a
// per-finding failure as an error — those are recorded as finding outcomes; a
// returned error means the run could not proceed (clone/scan failure).
func Run(ctx context.Context, cfg Config, deps Deps) (RunReport, error) {
	rep := RunReport{RunID: newRunID(), Repo: cfg.RepoURL, StartedAt: time.Now()}
	red := scan.NewRedactor()
	defer func() {
		rep.EndedAt = time.Now()
		rep.estimateCost()
	}()

	// Clone.
	workdir := cfg.Workdir
	if workdir == "" {
		tmp, err := os.MkdirTemp("", "codesucks-*")
		if err != nil {
			return rep, err
		}
		workdir = tmp
	}
	cloneDir := filepath.Join(workdir, "repo")
	r, err := deps.Clone(ctx, cfg.RepoURL, cfg.GitHubToken, cloneDir)
	if err != nil {
		return rep, fmt.Errorf("clone: %w", err)
	}

	sb, err := repo.NewSandbox(r.Dir)
	if err != nil {
		return rep, err
	}

	stack := gates.DetectStack(r.Dir)
	rep.Stack = string(stack.Kind)

	// Pristine baselines for Gates B and C (before any patch).
	lintBase := gates.CaptureLintBaseline(ctx, deps.Runner, r.Dir, stack, cfg.LintCmd)
	appBase := gates.CaptureAppBaseline(ctx, deps.Runner, r.Dir, stack, cfg.VerifyCmd)

	// Scan (Semgrep and TruffleHog in parallel).
	findings, err := runScan(ctx, deps, r.Dir, red)
	if err != nil {
		return rep, fmt.Errorf("scan: %w", err)
	}
	findings = scan.Filter(findings)
	rep.Found = len(findings)

	// Triage (parallel worker pool, read-only).
	triaged := agent.TriageAll(ctx, deps.LLM, TriageModel, sb, findings, TriageConcurrency, cfg.Budget())

	verdicts := make(map[string]agent.TriageVerdict)
	outcomes := make(map[string]*FindingOutcome)
	var actionable []scan.Finding

	for _, tf := range triaged {
		rep.Triaged++
		rep.TriageTokens.Add(tf.Usage)
		oc := newOutcome(tf.Finding)

		switch {
		case tf.Err != nil:
			oc.Status = StatusNeedsReview
			oc.Detail = "triage did not complete: " + red.Redact(tf.Err.Error())
			rep.NeedsReview++
		case tf.Verdict.Verdict == agent.VerdictFalsePositive:
			oc.Status = StatusFalsePositive
			oc.Detail = red.Redact(tf.Verdict.Rationale)
			rep.Skipped++
		case tf.Verdict.Verdict == agent.VerdictTruePositive && tf.Verdict.Confidence >= TriageConfidence:
			oc.Status = StatusTruePositive
			oc.Detail = red.Redact(tf.Verdict.Rationale)
			rep.TruePositive++
			verdicts[tf.Finding.Fingerprint] = tf.Verdict
			actionable = append(actionable, tf.Finding)
		default:
			oc.Status = StatusNeedsReview
			oc.Detail = fmt.Sprintf("verdict %q at confidence %.2f", tf.Verdict.Verdict, tf.Verdict.Confidence)
			rep.NeedsReview++
		}
		outcomes[tf.Finding.Fingerprint] = oc
	}

	if !cfg.DryRun {
		// Most-severe first.
		sort.SliceStable(actionable, func(i, j int) bool {
			return actionable[i].Severity.MoreSevereThan(actionable[j].Severity)
		})

		opened := 0
		for _, f := range actionable {
			oc := outcomes[f.Fingerprint]
			if opened >= cfg.MaxPRs {
				oc.Status = StatusSkippedCap
				oc.Detail = "PR cap reached for this run"
				rep.Skipped++
				continue
			}
			patchOne(ctx, cfg, deps, r, sb, stack, lintBase, appBase, f, verdicts[f.Fingerprint], red, oc, &rep)
			if oc.Status == StatusPatchedPR {
				opened++
			}
		}
	}

	// Assemble finding list in the original (severity-sorted) order.
	for _, f := range findings {
		if oc := outcomes[f.Fingerprint]; oc != nil {
			rep.Findings = append(rep.Findings, *oc)
		}
	}

	if err := WriteReports(cfg.OutDir, rep, red); err != nil {
		return rep, fmt.Errorf("write reports: %w", err)
	}
	return rep, nil
}

// patchOne runs the patch→verify→PR sequence for one confirmed finding,
// mutating oc and the report counters in place.
func patchOne(ctx context.Context, cfg Config, deps Deps, r *repo.Repo, sb *repo.Sandbox, stack gates.Stack, lintBase gates.LintBaseline, appBase gates.AppBaseline, f scan.Finding, v agent.TriageVerdict, red *scan.Redactor, oc *FindingOutcome, rep *RunReport) {
	branch := branchName(f)
	if err := r.CutBranch(ctx, branch); err != nil {
		oc.Status = StatusNeedsReview
		oc.Detail = "could not create fix branch: " + err.Error()
		rep.NeedsReview++
		return
	}
	defer r.ResetToBase(ctx)

	rescan := deps.rescanner(f.Tool, r.Dir, red)
	prePatch, err := rescan(ctx, []string{f.File})
	if err != nil {
		oc.Status = StatusNeedsReview
		oc.Detail = "pre-patch scan failed: " + red.Redact(err.Error())
		rep.NeedsReview++
		return
	}

	feedback := ""
	for attempt := 0; attempt <= PatchRetries; attempt++ {
		if attempt > 0 { // discard the failed attempt's edits before retrying
			r.ResetToBase(ctx)
			r.CutBranch(ctx, branch)
		}

		proposal, usage, err := agent.Patch(ctx, deps.LLM, cfg.PatchModel, sb, f, feedback, cfg.Budget())
		rep.PatchTokens.Add(usage)
		if err != nil {
			oc.Status = StatusNeedsReview
			oc.Detail = "patch agent did not complete: " + red.Redact(err.Error())
			rep.NeedsReview++
			return
		}

		if err := applyEdits(sb, proposal.Edits); err != nil {
			feedback = "applying your edits failed: " + err.Error()
			continue
		}
		changed, err := r.ChangedFiles(ctx)
		if err != nil || len(changed) == 0 {
			feedback = "your edits produced no changes to the working tree"
			continue
		}

		gs, passed, failDetail := runGates(ctx, cfg, deps, r, stack, lintBase, appBase, f, prePatch, changed, rescan)
		if !passed {
			feedback = failDetail
			continue
		}

		// All gates passed → commit, push, open PR.
		if err := r.CommitAll(ctx, commitMessage(f, proposal)); err != nil {
			oc.Status = StatusNeedsReview
			oc.Detail = "commit failed: " + err.Error()
			rep.NeedsReview++
			return
		}
		if err := r.Push(ctx, cfg.GitHubToken, branch); err != nil {
			oc.Status = StatusNeedsReview
			oc.Detail = "push failed: " + red.Redact(err.Error())
			rep.NeedsReview++
			return
		}
		num, url, err := deps.OpenPR(ctx, repo.PRInput{
			Owner: r.Owner, Repo: r.Name, Head: branch, Base: r.DefaultBranch,
			Title: prTitle(f), Body: BuildPRBody(f, v, proposal, gs, red),
		})
		if err != nil {
			oc.Status = StatusNeedsReview
			oc.Detail = "opening the PR failed: " + red.Redact(err.Error())
			rep.NeedsReview++
			return
		}
		oc.Status = StatusPatchedPR
		oc.Detail = proposal.Summary
		oc.PRNumber = num
		oc.PRURL = url
		oc.Gates = gs
		rep.Patched++
		rep.PRd++
		return
	}

	oc.Status = StatusPatchFailed
	oc.Detail = "no patch passed verification after retries: " + feedback
	rep.Skipped++
}

// runGates runs Gates A, B, and C in order, stopping at the first failure.
func runGates(ctx context.Context, cfg Config, deps Deps, r *repo.Repo, stack gates.Stack, lintBase gates.LintBaseline, appBase gates.AppBaseline, f scan.Finding, prePatch []scan.Finding, changed []string, rescan gates.Rescanner) (results []gates.Result, passed bool, failDetail string) {
	gateA, err := gates.VerifyFix(ctx, f, prePatch, changed, rescan)
	if err != nil {
		return results, false, "fix verification errored: " + err.Error()
	}
	results = append(results, gateA)
	if !gateA.Passed {
		return results, false, gateA.Detail
	}

	gateB := gates.Lint(ctx, deps.Runner, r.Dir, stack, cfg.LintCmd, lintBase)
	results = append(results, gateB)
	if !gateB.Passed {
		return results, false, gateB.Detail
	}

	gateC := gates.AppWorks(ctx, deps.Runner, r.Dir, stack, changed, appBase)
	results = append(results, gateC)
	if !gateC.Passed {
		return results, false, gateC.Detail
	}
	return results, true, ""
}

func runScan(ctx context.Context, deps Deps, dir string, red *scan.Redactor) ([]scan.Finding, error) {
	var sast, secrets []scan.Finding
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		sast, err = deps.Semgrep(gctx, dir)
		return err
	})
	g.Go(func() error {
		var err error
		secrets, err = deps.TruffleHog(gctx, dir, red)
		return err
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return append(sast, secrets...), nil
}

func applyEdits(sb *repo.Sandbox, edits []agent.Edit) error {
	for i, e := range edits {
		if err := sb.ApplyEdit(e.Path, e.OldStr, e.NewStr); err != nil {
			return fmt.Errorf("edit %d (%s): %w", i+1, e.Path, err)
		}
	}
	return nil
}

func newOutcome(f scan.Finding) *FindingOutcome {
	return &FindingOutcome{
		Fingerprint: f.Fingerprint,
		Tool:        string(f.Tool),
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		File:        f.File,
		Line:        f.StartLine,
	}
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func branchName(f scan.Finding) string {
	slug := slugRe.ReplaceAllString(strings.ToLower(f.RuleID), "-")
	slug = strings.Trim(slug, "-")
	if len(slug) > 40 {
		slug = slug[:40]
	}
	fp := f.Fingerprint
	if len(fp) > 8 {
		fp = fp[:8]
	}
	return fmt.Sprintf("fix/%s-%s-%s", f.Tool, slug, fp)
}

func commitMessage(f scan.Finding, p agent.PatchProposal) string {
	summary := p.Summary
	if summary == "" {
		summary = "apply security fix"
	}
	return fmt.Sprintf("fix(security): %s\n\n%s\n\nDetector: %s %s at %s:%d",
		summary, f.Message, f.Tool, f.RuleID, f.File, f.StartLine)
}

func newRunID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
