/**
 * Permission Gate
 *
 * Requires explicit approval before potentially destructive or privileged bash
 * commands and before Pi's filesystem tools access paths outside the directory
 * in which the agent session started.
 */

import { mkdir, readFile, realpath, rename, stat, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { CONFIG_DIR_NAME, isToolCallEventType, type ExtensionAPI } from "@earendil-works/pi-coding-agent";

type DangerousCommand = Readonly<{ name: string; pattern: RegExp }>;

/**
 * Dangerous-command categories whose match is considered *normal* risk: frequent,
 * reversible operations that may be remembered with a broad prefix rule
 * (e.g. `Bash(git add *)`). Every other category is high risk and may only be
 * remembered as an exact rule.
 */
const NORMAL_RISK_CATEGORIES: ReadonlySet<string> = new Set([
  "package installation or removal",
  "Git staging, commit, or push",
]);

/**
 * Tools invoked as `<tool> <subcommand> …` where the second token is a bounded
 * verb (so remembering `Bash(git add *)` is meaningful). Tools whose second token
 * is a variable target or file (`make <target>`, `node <file>`, `godot <flags>`)
 * are intentionally absent: they get a binary-only prefix such as `Bash(make *)`.
 */
const MULTI_VERB_TOOLS: ReadonlySet<string> = new Set([
  // version control
  "git",
  "gh",
  "glab",
  "hg",
  "svn",
  "jj",
  "bzr",
  "fossil",
  "git-lfs",
  // language package managers / toolchains
  "npm",
  "pnpm",
  "yarn",
  "bun",
  "deno",
  "pip",
  "pip3",
  "pipx",
  "poetry",
  "uv",
  "pdm",
  "hatch",
  "conda",
  "mamba",
  "gem",
  "bundle",
  "bundler",
  "cargo",
  "rustup",
  "go",
  "composer",
  "mix",
  "rebar3",
  "stack",
  "cabal",
  "dotnet",
  "nuget",
  "dub",
  "opam",
  "nimble",
  "luarocks",
  "swift",
  "flutter",
  "dart",
  "pod",
  // containers / orchestration
  "docker",
  "podman",
  "nerdctl",
  "buildah",
  "ctr",
  "crictl",
  "kubectl",
  "oc",
  "helm",
  "kustomize",
  "skaffold",
  "kind",
  "minikube",
  "k3d",
  "k9s",
  "docker-compose",
  "nomad",
  "vagrant",
  "packer",
  "kubectx",
  "kubens",
  "istioctl",
  "linkerd",
  "argocd",
  "flux",
  "velero",
  "eksctl",
  "kops",
  // cloud CLIs
  "aws",
  "gcloud",
  "gsutil",
  "bq",
  "az",
  "doctl",
  "ibmcloud",
  "oci",
  "heroku",
  "flyctl",
  "fly",
  "vercel",
  "netlify",
  "wrangler",
  "supabase",
  "firebase",
  "amplify",
  "railway",
  "render",
  "hcloud",
  "scaleway",
  "exoscale",
  "linode-cli",
  "sst",
  "sam",
  "eb",
  "serverless",
  "sls",
  "cdk",
  "cdktf",
  // infra / config management
  "terraform",
  "tofu",
  "pulumi",
  "ansible",
  "ansible-galaxy",
  "vault",
  "consul",
  "boundary",
  "waypoint",
  "salt",
  "salt-call",
  "knife",
  "act",
  "circleci",
  // system service / control
  "systemctl",
  "journalctl",
  "service",
  "launchctl",
  "timedatectl",
  "hostnamectl",
  "localectl",
  "loginctl",
  "machinectl",
  "busctl",
  "resolvectl",
  "networkctl",
  "systemd-analyze",
  // system package managers
  "brew",
  "port",
  "apt",
  "apt-get",
  "aptitude",
  "dpkg",
  "dnf",
  "yum",
  "rpm",
  "zypper",
  "pacman",
  "yay",
  "paru",
  "apk",
  "xbps-install",
  "emerge",
  "eopkg",
  "nix",
  "nix-env",
  "nix-channel",
  "guix",
  "snap",
  "flatpak",
  "choco",
  "scoop",
  "winget",
  "pkg",
  "pkgin",
  // databases / migrations
  "psql",
  "mysql",
  "mysqladmin",
  "mongo",
  "mongosh",
  "redis-cli",
  "sqlite3",
  "influx",
  "cqlsh",
  "clickhouse-client",
  "cockroach",
  "pgcli",
  "mycli",
  "prisma",
  "sequelize",
  "knex",
  "typeorm",
  "alembic",
  "flyway",
  "liquibase",
  "dbmate",
  "goose",
  "atlas",
  "migrate",
  "drizzle-kit",
  // web frameworks / scaffolding
  "rails",
  "artisan",
  "drush",
  "wp",
  "symfony",
  "django-admin",
  "ng",
  "vue",
  "nuxt",
  "nest",
  "remix",
  "astro",
  "expo",
  "eas",
  "react-native",
  "fastlane",
  // build / task orchestration with bounded verbs
  "mvn",
  "sbt",
  "lein",
  "pre-commit",
  "tox",
  "nox",
  "invoke",
  "nx",
  "turbo",
  "lerna",
  "rush",
  "moon",
  // security / secrets
  "openssl",
  "certbot",
  "mkcert",
  "step",
  "cfssl",
  "op",
  "bw",
  "sops",
  "pass",
  "gopass",
  "age",
  "ssh-keygen",
  "keytool",
  // data / ML
  "dvc",
  "mlflow",
  "wandb",
  "kaggle",
  "huggingface-cli",
  "hf",
  "dbt",
  "prefect",
  "dagster",
  "airflow",
  "kedro",
  "ollama",
  "llm",
  // misc bounded-verb tools
  "systemd-run",
  "etcdctl",
  "ipfs",
  "tea",
  "gitlab-runner",
]);

/** Rule capabilities. `edit`/`write` share the `write` capability; reads cover read/grep/find/ls. */
type Capability = "bash" | "read" | "write";

type BashRule = Readonly<{ capability: "bash"; glob: boolean; regex: RegExp; raw: string }>;
type PathRule = Readonly<{ capability: "read" | "write"; subtree: boolean; path: string; raw: string }>;
type Rule = BashRule | PathRule;

type ProjectPermissions = Readonly<{ allow: readonly Rule[]; deny: readonly Rule[] }>;

const EMPTY_PROJECT_PERMISSIONS: ProjectPermissions = { allow: [], deny: [] };

/** Shell command patterns that warrant confirmation even inside the project. */
const DANGEROUS_COMMANDS: readonly DangerousCommand[] = [
  {
    name: "file removal (rm)",
    pattern: /(?:^|[;&|()]|\s)(?:\S*\/)?rm\b/i,
  },
  { name: "secure or direct deletion", pattern: /\b(?:shred|srm|wipefs|unlink)\b|\bfind\b[^\n;&|]*\s-delete\b/i },
  { name: "privilege escalation", pattern: /(?:^|[;&|()]|\s)(?:sudo|doas|pkexec|su)\b/i },
  { name: "permission or ownership change", pattern: /\b(?:chmod|chown|chgrp|setfacl)\b/i },
  {
    name: "disk, partition, or mount operation",
    pattern:
      /\b(?:dd\b[^\n;&|]*\bof=\/dev\/|mkfs(?:\.[\w-]+)?|fdisk|parted|wipefs|mount|umount|diskutil\s+(?:erase|partition))/i,
  },
  {
    name: "system power or service operation",
    pattern: /\b(?:reboot|shutdown|poweroff|halt)\b|\bsystemctl\s+(?:stop|disable|mask|restart|reset-failed)\b/i,
  },
  { name: "process termination", pattern: /\b(?:killall|pkill)\b|\bkill\s+-?(?:9|KILL)\b/i },
  {
    name: "package installation or removal",
    pattern:
      /\b(?:apt(?:-get)?|dnf|yum|pacman|brew|npm|pnpm|yarn|pipx?|gem|cargo)\s+(?:install|remove|uninstall|purge|upgrade|update)\b/i,
  },
  { name: "download piped to a shell", pattern: /\b(?:curl|wget)\b[^\n;&|]*\|\s*(?:ba)?sh\b/i },
  { name: "remote command or file transfer", pattern: /\b(?:ssh|scp|sftp|rsync)\b/i },
  {
    name: "destructive Git operation",
    pattern:
      /\bgit\s+(?:reset\s+--hard|clean\b|push\b[^\n;&|]*(?:--force|-f\b)|stash\s+(?:drop|clear)|branch\s+[^\n;&|]*-[a-zA-Z]*D|tag\s+[^\n;&|]*-d|worktree\s+remove|update-ref\s+-d|reflog\s+(?:delete|expire))/i,
  },
  {
    name: "database deletion or flush",
    pattern: /\b(?:drop\s+(?:database|table|schema)|truncate\s+table|redis-cli\s+flush(?:all|db)|dropDatabase)\b/i,
  },
  {
    name: "container or orchestration deletion",
    pattern:
      /\b(?:docker\s+(?:rm|rmi|system\s+prune|volume\s+prune)|docker\s+compose\s+down\b[^\n;&|]*-v|kubectl\s+delete|helm\s+uninstall)\b/i,
  },
  {
    name: "infrastructure destruction",
    pattern:
      /\b(?:terraform\s+(?:destroy|apply\b[^\n;&|]*-destroy)|pulumi\s+destroy|aws\s+s3\s+rm|gcloud\s+projects\s+delete)\b/i,
  },
  {
    name: "broad filesystem write or extraction",
    pattern: /\b(?:rmdir|truncate|dd|mktemp|unzip|tar\s+-[^\n;&|]*x|7z\s+x)\b/i,
  },
  { name: "filesystem attribute or umask change", pattern: /\b(?:umask|chattr|attr)\b/i },
  {
    name: "outbound network or clipboard access",
    pattern:
      /\b(?:curl|wget|httpie?|nc|ncat|netcat|socat|ftp|telnet|sendmail|mail|mutt|msmtp|dig|nslookup|host|xclip|xsel|pbcopy|wl-copy)\b/i,
  },
  {
    name: "network listener or tunnel",
    pattern:
      /\b(?:python\s+-m\s+http\.server|nc\s+-l|ncat\s+-l|socat\b|ngrok|localtunnel|cloudflared\s+tunnel|ssh\s+[^\n;&|]*-R)\b/i,
  },
  {
    name: "dynamic or encoded code execution",
    pattern: /\b(?:eval|exec|source|xargs|base64\s+-d|xxd|od|python\s+-c|node\s+-e|ruby\s+-e|perl\s+-e)\b/i,
  },
  {
    name: "pipe to a shell or interpreter",
    pattern: /\|\s*(?:(?:ba|z|k|c|tc|da)?sh|python\d?|perl|ruby|node)\b/i,
  },
  {
    name: "additional package installation or custom registry",
    pattern:
      /\b(?:dpkg\s+-i|snap\s+(?:install|remove)|npx\b|go\s+install|make\s+install|cmake\s+--install|ninja\s+install)\b|(?:^|\s)--(?:index-url|registry)\b/i,
  },
  {
    name: "persistent or resource-control process change",
    pattern:
      /(?:^|[;&|()]|\s)(?:nohup|disown|screen|tmux|nice|renice|ionice|cpulimit|ulimit|cgroups?)\b|(?<![&>])&(?![&>])/i,
  },
  {
    name: "user, authentication, or namespace change",
    pattern: /\b(?:useradd|userdel|usermod|groupadd|passwd|visudo|chroot|unshare|nsenter|setcap|getcap)\b/i,
  },
  {
    name: "Git staging, commit, or push",
    pattern: /\bgit\s+(?:add|commit|push)\b/i,
  },
  {
    name: "discard working-tree changes (git)",
    pattern:
      /\bgit\s+(?:checkout|restore|switch)\b(?=[^\n;&|]*(?:\s\.(?:\s|$)|\s--(?:\s|$)|--force|\s-[a-z]*f\b|\.[a-z]{1,5}\b))/i,
  },
  {
    name: "Git history rewrite or remote change",
    pattern:
      /\bgit\s+(?:remote\s+(?:add|set-url|remove|rename)|rebase|filter-(?:branch|repo))\b|\bgh\s+(?:pr\s+(?:create|merge|close)|release\s+create|api|repo\s+(?:create|delete))\b/i,
  },
  {
    name: "container build, execution, or deployment",
    pattern:
      /\b(?:docker|podman|buildah|nerdctl)\s+(?:run|exec|build|push|compose)\b|\b(?:kubectl\s+(?:apply|exec|edit)|helm\s+(?:install|upgrade)|vagrant\s+(?:up|destroy|ssh))\b/i,
  },
  {
    name: "cloud or configuration-management operation",
    pattern:
      /\b(?:aws|gcloud|az|ansible-playbook|salt|chef-client|flyctl|vercel|netlify|heroku)\b|\bterraform\s+apply\b|\bpulumi\s+up\b/i,
  },
  {
    name: "database client or migration operation",
    pattern:
      /\b(?:psql|mysql|mongosh|redis-cli|sqlite3|mysqldump|pg_dump|rails\s+db:drop|prisma\s+migrate\s+reset|alembic\s+downgrade|diesel\s+migration\s+revert)\b/i,
  },
  {
    name: "kernel, device, scheduler, or network configuration",
    pattern:
      /\b(?:mkswap|losetup|modprobe|insmod|rmmod|depmod|sysctl|dmesg|crontab|\bat\b|batch|iptables|nftables|ufw|firewalld|ifconfig|route|hostnamectl|nmcli|wg|openvpn|wireguard)\b/i,
  },
  {
    name: "log, history, or clock tampering",
    pattern:
      /\b(?:history\s+-[cw]|unset\s+HISTFILE|logrotate|date\s+-s|timedatectl\s+set-time|hwclock\s+--set|tzselect)\b/i,
  },
  {
    name: "environment variable dump",
    pattern: /(?:^|[;&|()]|\s)(?:printenv|env)\s*(?:$|[;&|])/i,
  },
  {
    name: "secret-bearing or heredoc command",
    pattern: /\b(?:API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIALS)\b|<<[-~]?\s*['"]?\w+/i,
  },
  {
    name: "secret read piped onward",
    pattern:
      /\b(?:cat|less|head|tail|strings)\b[^\n;&|]*(?:\.env|\.pem|id_[a-z]+|credentials|secrets?|tokens?)[^\n;&|]*\|/i,
  },
];

const SENSITIVE_PATHS: readonly DangerousCommand[] = [
  {
    name: "credential or secret file",
    pattern:
      /(?:^|\/)(?:\.env(?:\.[^/]*)?|[^/]+\.(?:pem|key|crt|p12|jks)|id_[^/]*|known_hosts|credentials|cookies?|secrets?|tokens?|passwords?)(?:$|\/)/i,
  },
  {
    name: "shell, package, or authentication configuration",
    pattern:
      /(?:^|\/)(?:\.(?:bashrc|profile|zshrc|gitconfig|npmrc|pypirc|netrc)|\.ssh|\.gnupg|\.aws|\.azure|\.kube|\.config\/(?:gcloud|azure|gh))(?:$|\/)/i,
  },
  {
    name: "Git hook or CI/build configuration",
    pattern:
      /(?:^|\/)(?:\.git\/hooks|\.github\/workflows|\.gitlab-ci\.yml|Jenkinsfile|\.circleci\/config\.yml|Makefile|Dockerfile|docker-compose\.ya?ml|Procfile|\.husky)(?:$|\/)/i,
  },
  { name: "system configuration or device path", pattern: /^(?:\/(?:etc|usr|var|opt|dev|proc|sys)|~\/)/i },
];

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === "string")
    .map((item) => item.trim())
    .filter(Boolean);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Parse a rule string such as `Bash(git add *)`, `Read(../shared/config.json)`, or
 * `Write(dist/*)`. `Edit(...)` is accepted as an alias for the `write` capability.
 * A trailing/embedded `*` marks a glob (bash) or subtree (path) rule. Returns
 * undefined for anything that does not parse, so malformed entries are ignored.
 */
function parseRule(value: string): Rule | undefined {
  const match = /^(bash|read|write|edit)\((.*)\)$/is.exec(value.trim());
  if (!match) return undefined;
  const capabilityRaw = match[1].toLowerCase();
  const capability: Capability = capabilityRaw === "edit" ? "write" : (capabilityRaw as Capability);
  const pattern = match[2];
  if (capability === "bash") {
    const glob = pattern.includes("*");
    const regex = new RegExp(`^${pattern.split("*").map(escapeRegExp).join(".*")}$`);
    return { capability, glob, regex, raw: value.trim() };
  }
  const subtree = pattern.endsWith("*");
  const path = subtree ? pattern.replace(/\/?\*+$/, "") : pattern;
  return { capability, subtree, path, raw: value.trim() };
}

function parseRules(value: unknown): Rule[] {
  const rules: Rule[] = [];
  for (const entry of stringArray(value)) {
    const rule = parseRule(entry);
    if (rule) rules.push(rule);
  }
  return rules;
}

function parseProjectPermissions(value: unknown): ProjectPermissions {
  if (!value || typeof value !== "object" || Array.isArray(value)) return EMPTY_PROJECT_PERMISSIONS;
  const config = value as { allow?: unknown; deny?: unknown };
  return { allow: parseRules(config.allow), deny: parseRules(config.deny) };
}

function mergePermissions(a: ProjectPermissions, b: ProjectPermissions): ProjectPermissions {
  return { allow: [...a.allow, ...b.allow], deny: [...a.deny, ...b.deny] };
}

async function loadJson(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return undefined;
  }
}

async function writeJsonAtomic(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = `${path}.${process.pid}.tmp`;
  await writeFile(temporaryPath, `${JSON.stringify(value, undefined, 2)}\n`, "utf8");
  await rename(temporaryPath, path);
}

const PERMISSIONS_FILE = "permissions.json";
const LOCAL_PERMISSIONS_FILE = "permissions.local.json";

function permissionsFilePath(projectRoot: string, scope: RuleScope): string {
  return join(projectRoot, CONFIG_DIR_NAME, scope === "local" ? LOCAL_PERMISSIONS_FILE : PERMISSIONS_FILE);
}

type RuleScope = "local" | "shared";

/** Append a rule string to the chosen permissions file, keeping the `allow` list sorted and unique. */
async function persistAllowRule(projectRoot: string, rule: string, scope: RuleScope): Promise<void> {
  const path = permissionsFilePath(projectRoot, scope);
  const existing = await loadJson(path);
  const config: Record<string, unknown> =
    existing && typeof existing === "object" && !Array.isArray(existing) ? { ...existing } : {};
  config.allow = [...new Set([...stringArray(config.allow), rule])].sort();
  await writeJsonAtomic(path, config);
  if (scope === "local") await ensureLocalFileIgnored(projectRoot);
}

/** Keep the personal permissions file out of version control via `.pi/.gitignore`. */
async function ensureLocalFileIgnored(projectRoot: string): Promise<void> {
  const gitignorePath = join(projectRoot, CONFIG_DIR_NAME, ".gitignore");
  let contents = "";
  try {
    contents = await readFile(gitignorePath, "utf8");
  } catch {
    contents = "";
  }
  if (contents.split(/\r?\n/).some((line) => line.trim() === LOCAL_PERMISSIONS_FILE)) return;
  const prefix = contents.length > 0 && !contents.endsWith("\n") ? `${contents}\n` : contents;
  await mkdir(dirname(gitignorePath), { recursive: true });
  await writeFile(gitignorePath, `${prefix}${LOCAL_PERMISSIONS_FILE}\n`, "utf8");
}

function matchingPatterns(value: string, patterns: readonly DangerousCommand[]): string[] {
  return patterns.filter(({ pattern }) => pattern.test(value)).map(({ name }) => name);
}

function matchingDangerousCommands(command: string): string[] {
  return matchingPatterns(command, DANGEROUS_COMMANDS);
}

function matchingSensitivePaths(path: string): string[] {
  return matchingPatterns(path, SENSITIVE_PATHS);
}

/**
 * Split a shell command into candidate path/filename arguments. Redirect operators,
 * pipes, separators, and subshell punctuation are treated as delimiters so that a
 * redirect target such as `> .git/hooks/pre-commit` is isolated as its own token.
 */
function bashPathCandidates(command: string): string[] {
  return command
    .split(/[\s;&|()<>{}]+/)
    .map((token) => token.replace(/^[@=]+/, "").replace(/^['"]+|['"]+$/g, ""))
    .filter(Boolean);
}

/**
 * Apply the sensitive-path patterns to each argument of a shell command. The gate's
 * structured filesystem tools receive a bare path (anchored at `^`); bash commands
 * embed the path mid-string, so we tokenize first and test each token individually.
 */
function matchingSensitiveBashPaths(command: string): string[] {
  const names = new Set<string>();
  for (const token of bashPathCandidates(command)) {
    for (const name of matchingSensitivePaths(token)) names.add(name);
  }
  return [...names];
}

/** Match a value (normalized command, or path prefix) against the bash rules of a scope. */
function matchingBashRules(value: string, rules: readonly Rule[]): BashRule[] {
  return rules.filter((rule): rule is BashRule => rule.capability === "bash" && rule.regex.test(value));
}

/** Project deny rules (any glob) that a command trips; these always force a prompt. */
function matchingBashDenyRules(normalizedCommand: string, permissions: ProjectPermissions): string[] {
  return matchingBashRules(normalizedCommand.trim(), permissions.deny).map((rule) => `project deny: ${rule.raw}`);
}

/**
 * Shell metacharacters that can chain a second command or redirect I/O. A command
 * containing any of these is never auto-allowed by a rule and is never remembered:
 * a `*` in a prefix rule must never be allowed to span an operator that introduces
 * new behavior (`git log *` must not authorize `git log; rm -rf /`).
 */
function hasShellMetacharacter(command: string): boolean {
  return /[\n;`&|<>]/.test(command) || command.includes("$(");
}

/** True when any trigger in the match set is high risk (remembered only as an exact rule). */
function isHighRisk(matches: readonly string[]): boolean {
  return matches.some(
    (match) =>
      match.startsWith("sensitive path") ||
      match === "path outside the project" ||
      (!NORMAL_RISK_CATEGORIES.has(match) && !match.startsWith("project deny")),
  );
}

/**
 * Decide whether an already-flagged bash command is covered by an allow rule.
 * Deny rules and the metacharacter guard both force a prompt; high-risk commands
 * may be silenced only by an exact (non-glob) allow rule.
 */
function isBashCommandAllowed(
  rawCommand: string,
  normalizedCommand: string,
  matches: readonly string[],
  permissions: ProjectPermissions,
): boolean {
  if (hasShellMetacharacter(rawCommand) || hasShellMetacharacter(normalizedCommand)) return false;
  if (matches.some((match) => match.startsWith("project deny"))) return false;
  const highRisk = isHighRisk(matches);
  return matchingBashRules(normalizedCommand.trim(), permissions.allow).some((rule) => !(highRisk && rule.glob));
}

function isCommandWord(token: string): boolean {
  return /^[A-Za-z][\w.+-]*$/.test(token);
}

function toolBaseName(token: string): string {
  const slash = token.lastIndexOf("/");
  return slash >= 0 ? token.slice(slash + 1) : token;
}

/**
 * Build the rule string suggested for "Always allow". Returns undefined when no
 * safe rule can be formed (the command contains shell metacharacters). High-risk
 * commands are remembered exactly; normal-risk commands are generalized to a
 * `<tool> [subcommand] *` prefix.
 */
function suggestBashRule(normalizedCommand: string, highRisk: boolean): string | undefined {
  const command = normalizedCommand.trim();
  if (command.length === 0 || hasShellMetacharacter(command)) return undefined;
  if (highRisk) return `Bash(${command})`;

  const tokens = command.split(/\s+/);
  if (!isCommandWord(tokens[0])) return `Bash(${command})`;
  const prefix = [tokens[0]];
  if (MULTI_VERB_TOOLS.has(toolBaseName(tokens[0])) && tokens[1] && isCommandWord(tokens[1])) {
    prefix.push(tokens[1]);
  }
  return `Bash(${prefix.join(" ")} *)`;
}

/**
 * Apply inexpensive shell normalization before matching. This intentionally is
 * not a shell interpreter; it covers common syntactic evasions without
 * executing any part of the command.
 */
function normalizeCommand(command: string, aliases: ReadonlyMap<string, string>): string {
  let normalized = command
    .normalize("NFKC")
    .replace(/[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]/g, "")
    .replace(/\\([A-Za-z])/g, "$1")
    .replace(/(['"])([A-Za-z][\w-]*)\1/g, "$2");

  const variables = new Map<string, string>();
  for (const match of normalized.matchAll(/(?:^|[;&|()]|\s)([A-Za-z_]\w*)=(['"]?)([^\s;'"`]+)\2/g)) {
    variables.set(match[1], match[3]);
  }
  for (let pass = 0; pass < 3; pass += 1) {
    normalized = normalized.replace(/\$\{?([A-Za-z_]\w*)\}?/g, (reference, name: string) => {
      return variables.get(name) ?? reference;
    });
  }

  normalized = normalized.replace(
    /(?:^|([;&|()]|\s))(?:command|env(?:\s+[A-Za-z_]\w*=[^\s]+)*)\s+/g,
    (_match, prefix: string | undefined) => prefix ?? "",
  );
  for (const [name, value] of aliases) {
    normalized = normalized.replace(new RegExp(`(^|[;&|()]|\\s)${name}\\b`, "g"), `$1${value}`);
  }
  return normalized;
}

function isPrintableText(value: string): boolean {
  return [...value].every((character) => {
    const code = character.charCodeAt(0);
    return code === 9 || code === 10 || code === 13 || (code >= 32 && code <= 126);
  });
}

/** Beyond this length a single command is treated as complex rather than pattern-scanned exhaustively. */
const MAX_COMMAND_LENGTH = 2000;
/** Bounds on base64 scanning, so a large blob cannot dominate matching time. */
const MAX_BASE64_PAYLOADS = 5;
const MAX_BASE64_LENGTH = 4096;

function decodedBase64Payloads(command: string): string {
  return [...command.matchAll(/[A-Za-z0-9+/]{50,}={0,2}/g)]
    .slice(0, MAX_BASE64_PAYLOADS)
    .map(([payload]) => Buffer.from(payload.slice(0, MAX_BASE64_LENGTH), "base64").toString("utf8"))
    .filter(isPrintableText)
    .join("\n");
}

function recordAliases(command: string, aliases: Map<string, string>) {
  for (const match of command.matchAll(/\balias\s+([A-Za-z_]\w*)=(['"])([^'"\n]+)\2/g)) {
    aliases.set(match[1], match[3]);
  }
}

/** Resolve a path through existing symlinks while retaining a non-existent tail. */
async function canonicalize(path: string): Promise<string> {
  const missingSegments: string[] = [];
  let candidate = resolve(path);

  while (true) {
    try {
      return resolve(await realpath(candidate), ...missingSegments.reverse());
    } catch {
      const parent = dirname(candidate);
      if (parent === candidate) return resolve(path);
      missingSegments.push(basename(candidate));
      candidate = parent;
    }
  }
}

function isOutsideProject(path: string, projectRoot: string, cwd: string): Promise<boolean> {
  const normalizedPath = path.startsWith("@") ? path.slice(1) : path;
  const target = resolve(cwd, normalizedPath);

  return Promise.all([canonicalize(projectRoot), canonicalize(target)]).then(([root, resolvedTarget]) => {
    const pathFromRoot = relative(root, resolvedTarget);
    return pathFromRoot === ".." || /^\.\.[\\/]/.test(pathFromRoot) || isAbsolute(pathFromRoot);
  });
}

/** Detect simple shell path arguments that escape the project boundary. */
async function hasExternalPathReference(command: string, projectRoot: string, cwd: string): Promise<boolean> {
  const references = [...command.matchAll(/(?:^|[\s'"=])((?:\.\.\/|~\/|\/)[^\s'"`;&|)]*)/g)].map((match) => match[1]);
  if (references.some((path) => path.startsWith("~/"))) return true;

  for (const path of references) {
    if (await isOutsideProject(path, projectRoot, cwd)) return true;
  }
  return false;
}

function stripPathPrefix(path: string): string {
  return path.startsWith("@") ? path.slice(1) : path;
}

function unquoteToken(token: string): string {
  return token.replace(/^['"]|['"]$/g, "");
}

/**
 * Extract destination paths a shell command would truncate or overwrite:
 * truncating redirects (`>`, `&>`, `2>`, but not `>>` or `>&1`), and the destinations
 * of `mv`/`cp`, and `tee` without `--append`. Extraction is deliberately generous — the
 * caller only flags candidates that actually exist as files, so spurious tokens are inert.
 */
function overwriteCandidates(command: string): string[] {
  const targets: string[] = [];
  for (const match of command.matchAll(/(?:^|[\s&])(?:\d*>|&>)(?![>&])\|?\s*("[^"]*"|'[^']*'|[^\s;&|<>()]+)/g)) {
    targets.push(unquoteToken(match[1]));
  }
  for (const match of command.matchAll(/\b(?:mv|cp)\b([^\n;&|]*)/gi)) {
    const args = match[1]
      .split(/\s+/)
      .map(unquoteToken)
      .filter((token) => token && !token.startsWith("-"));
    if (args.length >= 2) targets.push(args[args.length - 1]);
  }
  for (const match of command.matchAll(/\btee\b([^\n;&|]*)/gi)) {
    if (/(?:^|\s)(?:-a|--append)\b/.test(match[1])) continue;
    for (const token of match[1].split(/\s+/).map(unquoteToken)) {
      if (token && !token.startsWith("-")) targets.push(token);
    }
  }
  return [...new Set(targets)];
}

/** Candidate overwrite targets that already exist as regular files (a real data-destroying overwrite). */
async function existingFileOverwrites(command: string, cwd: string): Promise<string[]> {
  const hits: string[] = [];
  for (const target of overwriteCandidates(command)) {
    try {
      const info = await stat(resolve(cwd, stripPathPrefix(target)));
      if (info.isFile()) hits.push(target);
    } catch {
      // Missing or inaccessible target: creating a new file is not an overwrite.
    }
  }
  return hits;
}

/** Whether a filesystem path is covered by a path rule, resolving both through symlinks. */
async function pathRuleMatches(rule: PathRule, targetPath: string, base: string): Promise<boolean> {
  const [target, rulePath] = await Promise.all([
    canonicalize(resolve(base, stripPathPrefix(targetPath))),
    canonicalize(resolve(base, stripPathPrefix(rule.path))),
  ]);
  if (!rule.subtree) return target === rulePath;
  if (target === rulePath) return true;
  const rel = relative(rulePath, target);
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

/** Project deny rules (read or write) matching a path; capability-agnostic — deny protects the path. */
async function matchingPathDenyRules(path: string, permissions: ProjectPermissions, base: string): Promise<string[]> {
  const names: string[] = [];
  for (const rule of permissions.deny) {
    if (rule.capability === "bash") continue;
    if (await pathRuleMatches(rule, path, base)) names.push(rule.raw);
  }
  return names;
}

/**
 * Whether an already-flagged filesystem access is covered by an allow rule. Deny
 * rules force a prompt; a sensitive path may be silenced only by an exact (non-subtree)
 * rule of the matching capability.
 */
async function isPathAllowed(
  path: string,
  capability: "read" | "write",
  sensitiveMatches: readonly string[],
  matches: readonly string[],
  permissions: ProjectPermissions,
  base: string,
): Promise<boolean> {
  if (matches.some((match) => match.startsWith("project deny"))) return false;
  const highRisk = sensitiveMatches.length > 0;
  for (const rule of permissions.allow) {
    if (rule.capability !== capability) continue;
    if (highRisk && rule.subtree) continue;
    if (await pathRuleMatches(rule, path, base)) return true;
  }
  return false;
}

/** Build the rule string suggested for "Always allow" on a filesystem access. */
function suggestPathRule(path: string, capability: "read" | "write", subtree: boolean): string {
  const label = capability === "read" ? "Read" : "Write";
  const clean = stripPathPrefix(path);
  return subtree ? `${label}(${clean.replace(/\/+$/, "")}/*)` : `${label}(${clean})`;
}

type Decision = { block: true; reason: string } | undefined;

const ALLOW_ONCE = "Allow once";
const DENY = "Deny";
const REMEMBER_LOCAL = `Just me (${CONFIG_DIR_NAME}/${LOCAL_PERMISSIONS_FILE})`;
const REMEMBER_SHARED = `Share with project (${CONFIG_DIR_NAME}/${PERMISSIONS_FILE})`;

interface DecisionRequest {
  title: string;
  detail: string;
  suggestedRule: string | undefined;
  trusted: boolean;
  mode: string;
  hasUI: boolean;
  select: (title: string, options: string[]) => Promise<string | undefined>;
  blockedReason: string;
  unavailableReason: string;
  save: (rule: string, scope: RuleScope) => Promise<void>;
}

/** Present the uniform Deny / Allow Once / Always Allow prompt and act on the choice. */
async function decide(request: DecisionRequest): Promise<Decision> {
  if (!request.hasUI) {
    return {
      block: true,
      reason: `${request.unavailableReason}: confirmation is unavailable in ${request.mode} mode.`,
    };
  }

  const canRemember = request.suggestedRule !== undefined && request.trusted;
  const alwaysAllow = request.suggestedRule ? `Always allow · ${request.suggestedRule}` : undefined;
  const options = canRemember && alwaysAllow ? [ALLOW_ONCE, alwaysAllow, DENY] : [ALLOW_ONCE, DENY];
  const hint = request.suggestedRule && !canRemember ? "\n(Trust this project to remember approvals.)" : "";

  const choice = await request.select(`${request.title}\n${request.detail}${hint}`, options);
  if (choice === ALLOW_ONCE) return undefined;
  if (alwaysAllow && choice === alwaysAllow && request.suggestedRule) {
    const scopeChoice = await request.select(`Remember ${request.suggestedRule}`, [REMEMBER_LOCAL, REMEMBER_SHARED]);
    if (scopeChoice !== REMEMBER_LOCAL && scopeChoice !== REMEMBER_SHARED) {
      return { block: true, reason: request.blockedReason };
    }
    try {
      await request.save(request.suggestedRule, scopeChoice === REMEMBER_SHARED ? "shared" : "local");
      return undefined;
    } catch {
      return { block: true, reason: `${request.blockedReason}: could not save approval` };
    }
  }
  return { block: true, reason: request.blockedReason };
}

export default function permissionGate(pi: ExtensionAPI) {
  let projectRoot: string | undefined;
  let projectTrusted = false;
  let projectPermissions = EMPTY_PROJECT_PERMISSIONS;
  const aliases = new Map<string, string>();

  const saveRule = async (rule: string, scope: RuleScope): Promise<void> => {
    if (!projectRoot) throw new Error("no project root");
    await persistAllowRule(projectRoot, rule, scope);
    const parsed = parseRule(rule);
    if (parsed) projectPermissions = { ...projectPermissions, allow: [...projectPermissions.allow, parsed] };
  };

  pi.on("session_start", async (_event, ctx) => {
    aliases.clear();
    projectRoot = resolve(ctx.cwd);
    projectTrusted = ctx.isProjectTrusted();
    projectPermissions = EMPTY_PROJECT_PERMISSIONS;
    if (projectTrusted) {
      const shared = parseProjectPermissions(await loadJson(permissionsFilePath(projectRoot, "shared")));
      const local = parseProjectPermissions(await loadJson(permissionsFilePath(projectRoot, "local")));
      projectPermissions = mergePermissions(shared, local);
    }
  });

  pi.on("tool_call", async (event, ctx) => {
    const trusted = projectTrusted && projectRoot !== undefined;
    const select = ctx.ui.select.bind(ctx.ui);

    if (isToolCallEventType("bash", event)) {
      const rawCommand = event.input.command;
      recordAliases(rawCommand, aliases);
      const normalizedCommand = normalizeCommand(rawCommand, aliases);
      const inspectedCommand = [rawCommand, normalizedCommand, decodedBase64Payloads(normalizedCommand)]
        .filter(Boolean)
        .join("\n");

      const matches = matchingDangerousCommands(inspectedCommand);
      if (rawCommand.length > MAX_COMMAND_LENGTH) matches.push("long command");
      matches.push(...matchingBashDenyRules(normalizedCommand, projectPermissions));
      if (await hasExternalPathReference(inspectedCommand, projectRoot ?? ctx.cwd, ctx.cwd)) {
        matches.push("path outside the project");
      }
      for (const name of matchingSensitiveBashPaths(inspectedCommand)) {
        matches.push(`sensitive path (${name})`);
      }
      for (const target of await existingFileOverwrites(rawCommand, ctx.cwd)) {
        matches.push(`overwrites an existing file (${target})`);
      }
      if (matches.length === 0) return;
      if (isBashCommandAllowed(rawCommand, normalizedCommand, matches, projectPermissions)) return;

      const suggestedRule = suggestBashRule(normalizedCommand, isHighRisk(matches));
      return decide({
        title: "Allow this command?",
        detail: `matches: ${matches.join(", ")}\n\n${rawCommand}`,
        suggestedRule,
        trusted,
        mode: ctx.mode,
        hasUI: ctx.hasUI,
        select,
        blockedReason: `Blocked ${matches.join(", ")}`,
        unavailableReason: `Blocked ${matches.join(", ")}`,
        save: saveRule,
      });
    }

    const path =
      isToolCallEventType("read", event) ||
      isToolCallEventType("write", event) ||
      isToolCallEventType("edit", event) ||
      isToolCallEventType("grep", event) ||
      isToolCallEventType("find", event) ||
      isToolCallEventType("ls", event)
        ? event.input.path
        : undefined;

    if (!path) return;

    const base = projectRoot ?? ctx.cwd;
    const capability: "read" | "write" = event.toolName === "write" || event.toolName === "edit" ? "write" : "read";
    const outsideProject = await isOutsideProject(path, base, ctx.cwd);
    const sensitiveMatches = matchingSensitivePaths(path);
    const denyMatches = await matchingPathDenyRules(path, projectPermissions, base);

    const matches: string[] = [];
    if (outsideProject) matches.push("path outside the project");
    matches.push(...sensitiveMatches.map((name) => `sensitive path (${name})`));
    matches.push(...denyMatches.map((rule) => `project deny: ${rule}`));
    if (matches.length === 0) return;
    if (await isPathAllowed(path, capability, sensitiveMatches, matches, projectPermissions, base)) return;

    const operation = capability === "read" ? "read" : "modify";
    const subtree = event.toolName === "ls" || event.toolName === "find";
    return decide({
      title: `Allow Pi to ${operation} this path?`,
      detail: `${matches.join(", ")}\n\npath: ${path}`,
      suggestedRule: suggestPathRule(path, capability, subtree),
      trusted,
      mode: ctx.mode,
      hasUI: ctx.hasUI,
      select,
      blockedReason: `Blocked attempt to ${operation}: ${matches.join(", ")}`,
      unavailableReason: `Blocked attempt to ${operation} ${outsideProject ? "outside the project" : "a protected path"}`,
      save: saveRule,
    });
  });
}
