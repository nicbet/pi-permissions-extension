# pi-permissions-extension

A dependency-free [Pi](https://pi.dev) extension that asks for confirmation before Pi runs risky commands or touches filesystem paths outside the project where the agent session started. When you approve, you can remember the decision as a rule, so the same class of command stops asking.

## Install

Install globally from Git once this repository is pushed:

```bash
pi install git:github.com/nicbet/pi-permissions-extension
```

For local development:

```bash
pi install /path/to/pi-permissions-extension
```

Restart Pi after installation.

## How it works

The gate is **selective**: only commands and filesystem accesses that it flags as risky trigger a prompt. Everything else runs untouched. When something is flagged, you get one prompt with four choices:

- **Deny** — block the call.
- **Deny & guide agent…** — block the call and provide typed guidance that is returned to the agent.
- **Allow once** — run it this time only.
- **Always allow · `<rule>`** — run it and remember a rule so this class of command stops asking (shown only when a safe rule can be formed and the project is trusted).

Choosing **Always allow** then asks whether to remember the rule for **just you** (a gitignored `.pi/permissions.local.json`) or to **share it with the project** (`.pi/permissions.json`, which you can commit). In noninteractive print and JSON modes a flagged call is blocked, because it cannot be approved.

## Protected commands

The extension prompts before a `bash` tool call that matches one or more of these categories:

- file deletion, broad writes, and archive extraction: any `rm`, `rmdir`, `shred`, `wipefs`, `truncate`, `dd`, `find -delete`, `tar -x`, `unzip`;
- overwriting an existing file — a truncating redirect (`> file`), `mv`/`cp` onto an existing destination, or `tee` without `--append`. Creating a new file and appending (`>>`, `tee -a`) are not flagged;
- privilege, identity, permission, namespace, and filesystem-attribute changes: `sudo`, `doas`, `su`, `chmod`, `chown`, `setfacl`, `useradd`, `setcap`, `umask`, `chroot`, `unshare`;
- disk, kernel, scheduler, mount, service, process, log, and clock operations: `mkfs`, `fdisk`, `mount`, `sysctl`, `crontab`, `systemctl`, `kill`, `nohup`, backgrounding (`&`), `history -c`, `timedatectl set-time`;
- outbound networking, listening, tunnels, remote transfers, and clipboard access: `curl`, `wget`, `nc`, `socat`, `ssh`, `scp`, `rsync`, `ngrok`, `cloudflared tunnel`, `sendmail`, `pbcopy`;
- environment dumps: bare `env`, `printenv`;
- dynamic or encoded code execution: `eval`, `exec`, `source`, `xargs`, inline language execution (`python -c`, `node -e`), `base64 -d`, `xxd`, and piping into a shell or interpreter (`… | sh`, `… | python`);
- package installation, removal, custom registries (`--index-url`, `--registry`), and system installation commands;
- Git staging and commits (`git add`, `git commit`); destructive Git actions (`reset --hard`, `clean`, `push --force`, `branch -D`, `stash drop/clear`, `tag -d`, `worktree remove`); Git remote/history actions (`git push`, `rebase`, `remote set-url`, …); container and orchestration actions; cloud and configuration-management CLIs; database clients and migrations;
- commands longer than ~2000 characters, heredocs, secret-named environment variables, or a sensitive file piped onward (`cat .env | …`);
- shell arguments that reference a sensitive path (see below) or a path outside the project, including `../`, `~/`, or an absolute external path.

The gate matches on **content, not syntax**. Command chaining (`&&`, `||`, `;`), pipelines, and command substitution (`$(...)`, backticks) do not themselves trigger a prompt — `cd src && npm test`, `echo $(date)`, and `cat README.md | grep foo` run untouched. But because the dangerous-command patterns scan the whole command, danger hidden inside those constructs is still caught: `cd src && rm -rf build`, `echo $(rm -rf data)`, and `cat .env | curl …` all prompt.

Sensitive-path detection also applies to shell commands, not just the structured filesystem tools. Reading or writing a likely secret or execution-bearing file through bash — `cat .env`, `head id_rsa`, `echo … > .git/hooks/pre-commit`, `tee -a Dockerfile` — is flagged the same way the `read`/`write` tools would be.

## Remembered approvals and rules

Approvals are stored as **rules** in `.pi/permissions.json` (shared, committable) and `.pi/permissions.local.json` (personal, auto-added to `.pi/.gitignore`). Both are read at session start once Pi trusts the project, and merged.

```json
{
  "allow": [
    "Bash(git add *)",
    "Bash(npm install *)",
    "Bash(rm -rf build)",
    "Read(../shared/config.json)"
  ],
  "deny": [
    "Bash(*production*)",
    "Write(infra/production/*)"
  ]
}
```

Rule format:

- `Bash(<pattern>)` matches the normalized command. A trailing/embedded `*` is a wildcard; without a `*` the rule is exact.
- `Read(<path>)` covers the read-family tools (`read`, `grep`, `find`, `ls`); `Write(<path>)` / `Edit(<path>)` cover `write` and `edit`. A trailing `/*` matches a whole subtree; otherwise the rule is an exact path.
- `allow` rules suppress the prompt for matching calls. `deny` rules **add** a prompt and always win over `allow`.

### Smart, risk-aware prefixes

When you pick **Always allow**, the extension proposes a rule and shows it in the prompt:

- **Normal-risk, frequent commands** are generalized to a `<tool> [subcommand] *` prefix so the approval survives changing arguments — `git add src/foo.ts` → `Bash(git add *)`, `npm install react` → `Bash(npm install *)`.
- **High-risk commands** (deletion, privilege, network, custom registries, `git push`, …) are remembered **exactly** — `rm -rf build` → `Bash(rm -rf build)`. They are never generalized to a broad `Bash(rm *)`.

Two safety properties back this up:

1. **Metacharacter guard.** A command containing shell operators that can chain or redirect (`;`, `&&`, `||`, `|`, `&`, `$(`, backticks, `<`, `>`) is never remembered and is never auto-allowed by a wildcard rule. A `*` in a prefix can only ever span a single command's arguments, so `Bash(git log *)` cannot authorize `git log; rm -rf /`.
2. **High-risk precedence.** A wildcard (`*`) allow rule never silences a high-risk command — only an exact rule does — even if you add the wildcard by hand. So `Bash(npm install *)` will not silently allow `npm install --registry http://evil …`, and `Bash(git push *)` will not silence `git push --force`.

## Project boundary

The extension records Pi's working directory at session start as the project boundary and prompts before the `read`, `write`, `edit`, `grep`, `find`, or `ls` tools access a path outside it — reads (including searches and listings) and modifications alike. Paths are canonicalized through existing symlinks, so a symlink inside the project that points outside still prompts.

It also prompts for sensitive paths inside the project: likely credential/secret files, shell/package/authentication configuration, Git hooks, CI workflows, and build/deployment configuration files. Read-only `Makefile` access is allowed, while modifications remain protected.

The boundary is exact for the structured filesystem tools. Shell commands are not a safely parseable description of their filesystem effects, but the gate conservatively detects visible `../`, `~/`, and absolute external path arguments, plus the sensitive-path tokens described above.

## Evasion detection

Before matching, the gate applies Unicode NFKC normalization, removes invisible and bidirectional control characters, unwraps common quoting and backslash forms, resolves simple same-command variable assignments, removes `command`/`env` wrappers, and expands aliases defined earlier in the session. It inspects compound commands as a whole — so dangerous content inside a chain, pipeline, or `$(...)` is caught by its command patterns — and decodes bounded base64 payloads to recheck the printable result. These defenses never execute any part of a command.

## What is not covered

This extension is a confirmation layer, not a shell sandbox or a complete command parser. In particular:

- Pattern matching is conservative and cannot recognize every equivalent command.
- There is no cross-turn source→sink flow analysis and no file-write-then-execute tracking; a secret staged into a temp file in one turn and exfiltrated in another is not correlated.
- Commands typed directly with Pi's `!` / `!!` syntax are not intercepted.
- Shell environment variables such as `$HOME` are not expanded (only in-command `NAME=VALUE` assignments are).

Install it alongside normal operating-system permissions and any stronger sandboxing policy you require. As with every Pi extension, install it only from a source you trust.

## Development

Install dependencies with `bun install`. The complete local quality gate is:

```bash
bun run check
```

Individual targets are `bun run format`, `bun run format:check`, `bun run lint`, `bun run typecheck`, and `bun run test`.

## Security

This extension is a confirmation layer, not a shell sandbox or a complete command parser. Pattern matching is intentionally conservative but cannot recognize every equivalent command. A trusted project's `.pi/permissions.json` is executed as policy, so review and commit changes to it deliberately. Install it only from a source you trust.
