# Changelog

## [0.1.2] - 2026-08-20

### Approvals

- Emit an iTerm2-compatible desktop notification with a terminal-bell fallback when the gate is
  waiting for an approval decision.

## [0.1.1] - 2026-08-20

### Approvals

- Redesigned interactive approval requests as a Pi-style, pending-background box with a distinct
  heading, white command, dimmed reason, and keyboard-navigable choices.
- Added inline **Deny & guide agent** input. Its typed guidance is returned in the blocked result
  and sent as a queued user message to ensure the agent receives it.

### Calibration

- Avoid false positives for labels containing `host`, quoted ampersands, `find` filename predicates,
  read-only `Makefile` access, and `/dev/null` in shell commands.

## [0.1.0] - 2026-08-19

Initial release. A dependency-free Pi extension that asks for confirmation before Pi runs risky
commands or touches filesystem paths outside the project, and remembers approvals as rules.

### Gating

- Confirmation for destructive, privileged, remote, package-management, database, container, and
  infrastructure shell commands, plus a project-root boundary for Pi's `read`/`write`/`edit`/
  `grep`/`find`/`ls` tools (reads, searches, listings, and modifications).
- **Data-loss coverage:** any `rm` (not only recursive), the common `git clean` forms, and
  destructive Git (`reset --hard`, `push --force`, `branch -D`, `stash drop/clear`, `tag -d`,
  `worktree remove`, working-tree discards). Stat-based overwrite detection prompts only when a
  redirect / `mv` / `cp` / `tee` would clobber an existing file.
- Sensitive-path detection for shell commands (`cat .env`, `echo … > .git/hooks/pre-commit`) and
  environment-dump detection (`env`, `printenv`).

### Calibration

- Matches on **content, not syntax**: command chaining (`&&`, `||`, `;`), pipelines, and command
  substitution (`$(...)`) do not prompt on their own, but danger inside them still does.
- Git tuned for noise: `fetch`/`pull`/`clone`/`merge`/branch-switch stay quiet; `git push` is
  normal-risk and broadly rememberable; destructive/rewrite/discard forms still prompt.
- A locked calibration test suite (~60 benign commands that must stay quiet, ~55 dangerous that
  must always prompt) guards both failure modes.

### Approvals

- One uniform prompt — Deny / Allow Once / Always Allow — for every flagged call.
- Remembered approvals are rules in `.pi/permissions.json` (shared) and `.pi/permissions.local.json`
  (personal, gitignored automatically), using the flat `allow`/`deny` format
  (`Bash(git add *)`, `Read(../shared/config.json)`, `Write(dist/*)`).
- Smart, risk-aware prefixes: normal-risk commands generalize to a `<tool> [subcommand] *` prefix;
  high-risk commands are remembered exactly.
- Two safety properties: a metacharacter guard (chained/redirected commands are never rememberable
  or auto-allowed by a wildcard) and high-risk precedence (a wildcard rule never silences a
  high-risk command — only an exact rule does).

### Evasion detection

- Unicode NFKC normalization; removal of invisible/bidirectional control characters; unwrapping of
  quoting, backslash, and `command`/`env` wrappers; same-command variable and session alias
  expansion; bounded base64 decode-and-recheck; symlink-aware project-boundary checks.
