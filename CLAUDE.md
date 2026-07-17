# codesucks-ai — notes for Claude Code

Guidance for working in this repository.

## What this is

A simple agentic SAST pipeline in Go. Given a GitHub repo it: scans with Semgrep + TruffleHog (in parallel), triages findings with Claude to drop false positives, patches confirmed vulnerabilities with Claude, verifies each patch (re-scan → lint → tests/build, all baseline-compared), and opens one GitHub PR per verified fix.

**Design principles (keep these intact):**
- One command, one pipeline. No modes, no config files, no preset system, no fallback chains.
- CLI surface is fixed: 7 flags + a positional repo URL (see README). Tokens come from env / `.env` only. Do not add flags without a strong reason.
- All AI output arrives as tool-call inputs (`submit_triage` / `submit_patch`), never parsed from prose. All scanner output is read from `--json` files / NDJSON, never scraped from mixed stdout.
- A PR opens only after Gates A, B, and C all pass. Gates are deterministic Go, never model judgment.
- Never log or print raw secrets or tokens. The auth token is passed to git via env-based config, never argv. Every log/report/PR string goes through `scan.Redactor`.

## Commands

```bash
go build ./...        # build
go vet ./...          # vet
go test ./...         # unit + integration (integration self-skips without semgrep/node/trufflehog)
go test -race ./...   # race detector (agent + pipeline especially)
go build -o codesucks-ai ./cmd/codesucks-ai
```

Live end-to-end (opt-in, needs real keys, opens a real PR):
```bash
E2E=1 go test ./e2e/...
```

Test target repos: https://github.com/asii-mov/NodeGoat-AI-test (JS), https://github.com/coleam00/Archon (multi-language).

## Package map

- `internal/scan` — the single normalized `Finding` model, content-based `Fingerprint` (line-shift invariant; its disappearance after a patch is the Gate A signal), severity normalization, Semgrep (`RunSemgrep`, JSON-to-file) and TruffleHog (`RunTruffleHog`, NDJSON) adapters, `Redactor`, and `Filter` (drops INFO + vendored, dedups).
- `internal/repo` — `Clone` (shallow, token via env config), branch/commit/push/`ChangedFiles`, the path-guarded `Sandbox` (`ReadFile`/`ListDir`/`Search`/`ApplyEdit` — exactly-one-match), and `CreatePR` (go-github).
- `internal/agent` — the `LLM` interface (satisfied by the SDK, mocked in tests), the bounded tool-loop (`Run`), tool schemas, and `Triage`/`TriageAll`/`Patch`. Runs without extended thinking to keep forced-submission and history handling simple.
- `internal/gates` — `DetectStack`, `CommandRunner` seam, Gate A `VerifyFix`, Gate B `Lint` + `CaptureLintBaseline`, Gate C `AppWorks` + `CaptureAppBaseline` (build→syntax fallback ladder).
- `internal/pipeline` — `Config`/`ParseFlags`, `Deps` (injectable for tests), `Run` orchestration, `BuildPRBody`, and the `RunReport` writers.

## Conventions

- New functionality needs tests. Unit tests use fakes (scripted `fakeLLM`, `queueRunner`, grep-based fake scanners) and must be network-free. Real-tool tests `t.Skip` when the binary is absent.
- Keep gate logic deterministic and baseline-compared ("no *new* issues/failures"), so messy target repos with pre-existing noise don't block fixes.
- Model IDs: triage `claude-haiku-4-5`, patch `claude-opus-4-8` (default, overridable via `-model`). When touching Anthropic SDK code, confirm current model IDs / call shapes via the claude-api skill rather than from memory.
