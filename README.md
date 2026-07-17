# codesucks-ai

A simple agentic SAST pipeline. Point it at a GitHub repository and it will:

1. **Scan** the code with [Semgrep](https://semgrep.dev) (SAST) and [TruffleHog](https://github.com/trufflesecurity/trufflehog) (secret detection), run in parallel.
2. **Triage** every finding with Claude to reject false positives.
3. **Patch** each confirmed vulnerability with Claude.
4. **Prove** every patch before proposing it — the fix is re-scanned, the code is linted, and the app's tests/build still pass — each measured against a pristine baseline.
5. **Open one pull request per fix**, stating the vulnerability, severity, CWE, the solution taken, and the exact verification evidence.

One command, one pipeline, no modes, no config files.

## Install

Requires **Go 1.23+** and these tools on your `PATH`: `git`, `semgrep`, `trufflehog`.

```bash
go build -o codesucks-ai ./cmd/codesucks-ai
```

## Usage

```bash
codesucks-ai [flags] <github-repo-url>
```

Credentials come from the environment (or a local `.env` file):

```bash
export GITHUB_TOKEN=github_pat_...      # repo scope: clone, push fix branches, open PRs
export ANTHROPIC_API_KEY=sk-ant-...     # triage + patch agents
```

Example — scan a repo, verify fixes, and open up to one PR:

```bash
codesucks-ai -max-prs 1 https://github.com/asii-mov/NodeGoat-AI-test
```

Preview what it would do without changing anything:

```bash
codesucks-ai -dry-run https://github.com/asii-mov/NodeGoat-AI-test
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `-dry-run` | `false` | Scan and triage only — no patches, pushes, or PRs. |
| `-max-prs` | `10` | Maximum pull requests to open per run. |
| `-model` | `claude-opus-4-8` | Model for the patch agent. |
| `-lint-cmd` | (auto) | Override the Gate B lint command. |
| `-verify-cmd` | (auto) | Override the Gate C test/build command. |
| `-workdir` | (temp dir) | Where to clone the target. |
| `-out` | `./out` | Directory for `report.json` and `report.md`. |

That is the entire surface. Everything else is a sensible built-in constant (see below).

### Built-in constants

Deliberately not flags, to keep the tool simple:

- Triage model: `claude-haiku-4-5`; triage concurrency: 4; confidence threshold to act: 0.7.
- Per-finding budget: 12 agent iterations, 200k tokens, 5-minute wall clock.
- Patch retries on gate failure: 2.
- Semgrep config: `p/default`.
- `INFO`-severity findings are skipped, as are vendored/generated paths (`node_modules/`, `vendor/`, `dist/`, `build/`, `*.min.js`, `*_pb.go`, `*.generated.*`).

## How verification works

A pull request is opened only after all three gates pass, in order. Each is deterministic Go code, never a model judgment:

- **Gate A — fix verified.** The finding's scanner is re-run on the changed files. The original finding must be gone (its content-based fingerprint disappears) and no new findings may appear.
- **Gate B — lint.** The linter runs and must introduce no new issues versus a pristine baseline, so a repo's pre-existing lint noise never blocks a fix.
- **Gate C — app works.** The repo's tests (or, failing that, build → syntax check) run and must show no new failures versus a pristine baseline. The verification level that ran is recorded in the PR.

If a gate fails, the failure is fed back to the patch agent for another attempt (up to the retry limit); if it still fails, the finding is abandoned and recorded for human review. Secrets are never printed — every log line, report, and PR body is scrubbed, and secret PRs include a rotation reminder.

## Development

```bash
go build ./...          # build
go vet ./...            # vet
go test ./...           # unit + integration tests
go test -race ./...     # with the race detector
```

Integration tests that need `semgrep`, `trufflehog`, or `node` skip themselves when those tools are absent. The live end-to-end test is opt-in:

```bash
E2E=1 go test ./e2e/...   # requires GITHUB_TOKEN + ANTHROPIC_API_KEY; opens a real PR
```

## Layout

```
cmd/codesucks-ai/   CLI entry point
internal/scan/      normalized Finding model, fingerprinting, Semgrep + TruffleHog adapters, redactor
internal/repo/      git operations, path-guarded edit sandbox, GitHub PR creation
internal/agent/     Anthropic tool-loop, triage + patch agents
internal/gates/     Gates A/B/C, baselines, stack detection
internal/pipeline/  orchestration, PR body, run report
testdata/vuln-app/  intentionally vulnerable fixture app
e2e/                opt-in live end-to-end test
```
