# skedaddle-mcp

Check an open-source package **before an AI coding agent installs it**. A pre-install hook and an MCP server for npm,
PyPI and crates.io that blocks:

- names that do not exist (hallucinated or mistyped, the "slopsquatting" vector),
- known malware and packages npm has taken down,
- HIGH/CRITICAL CVEs in the exact version when a fixed version exists (it tells you which one),
- and **signs of a compromised release**: provenance attestation lost, a new publisher, an install script or new
  dependencies appearing in a patch release, a version that was published and then pulled.

No account, no API key, no telemetry. Apache-2.0.

```console
$ skedaddle-mcp check npm axios@1.14.1 | jq -r '"\(.verdict): \(.findings[0].message)"'
block: axios@1.14.1 was published on 2026-03-31T00:21:58.168Z and later removed from the registry (removal usually follows a compromise or malware report)
$ skedaddle-mcp check npm event-stream@3.3.5 | jq -r '"\(.verdict): \(.findings[0].message)"'
warn: event-stream@3.3.5 was published by 'right9ctrl', who published none of the previous 10 releases (dominictarr), without provenance
```

The full output is JSON: verdict, and each finding with its signal, severity, evidence and source URL.

## Why this exists

- Agents run `npm install` and `pip install` in shells nobody hardened. The package manager's own protections
  (release cooldowns, provenance checks, build-script allowlists) are off unless someone turned them on.
- Compromised releases are short-lived and high-impact. axios 1.14.1 was live for about three hours on 2026-03-31
  ([StepSecurity](https://stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)) on a
  package with about 108M weekly downloads ([opensourcemalware.com](https://opensourcemalware.com/blog/the-software-supply-chain-malware-landscape-january-may-2026));
  litellm 1.82.7/1.82.8 reached PyPI with a stolen token on 2026-03-24 ([HN](https://news.ycombinator.com/item?id=47501426)).
- On npm, OSV holds about 223,000 malicious-package records against about 8,100 ordinary advisories (counted from
  the [OSV npm dump](https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip), 2026-11-08; records, not incidents).
- LLMs invent package names: at least 5.2% of commercial-model and 21.7% of open-model code samples referenced a
  package that does not exist ([Spracklen et al., USENIX Security 2025](https://arxiv.org/abs/2406.10279)).
- The #1 reason developers mute security tools is noise: false positives and unactionable alerts
  ([npm maintainer survey, arXiv 2601.20240](https://arxiv.org/html/2601.20240v1)). So skedaddle stays quiet by
  default: ordinary CVEs are not reported, a fresh release alone is not a warning, and every finding carries the
  evidence and the URL it came from.

## Install

```bash
uv tool install git+https://github.com/altairzhambyl/skedaddle-mcp
skedaddle-mcp --version
```

### As a Claude Code pre-install hook (enforcing — recommended)

An MCP tool is advisory: the model may not call it. A hook runs on every shell command.

```bash
skedaddle-mcp install          # shows the change to ~/.claude/settings.json
skedaddle-mcp install --yes    # writes it (keeps a backup and your existing hooks)
```

Or add it by hand to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "skedaddle-mcp hook", "timeout": 60, "onFailure": "block" }] }
    ]
  }
}
```

`"onFailure": "block"` (Claude Code 2.1.295+) makes a crashed or timed-out hook block the command instead of letting it
run; skedaddle itself answers within `SKEDADDLE_HOOK_BUDGET` seconds (default 20) and asks about anything it did not
finish.

On **block** the agent is denied (the user can still run the command themselves). On **warn** the install proceeds
and the agent is told why. If a registry or OSV cannot be reached, the user is **asked** (set
`SKEDADDLE_ON_ERROR=allow` or `deny` to change that). Anything skedaddle cannot check is **asked about, never silently allowed**: a git/URL/
tarball source, a custom registry or index (`--registry`, `-i`, `--extra-index-url`, `npm_config_registry`,
`PIP_INDEX_URL`, `UV_INDEX_URL`, an index line inside a requirements file), or more than 50 packages in one command.
A bare `npm install` / `npm ci` after the agent edited `package.json` or the lockfile is checked too: dependencies the
lockfile does not pin yet, and lockfile entries that changed since git HEAD. `npm:` aliases are checked as the real
package; `cd dir && ...`, `sh -c '...'` and heredocs fed to a shell are followed. Registering an MCP server
(`claude mcp add NAME -- npx -y pkg`, `mcp add-json`) is checked like an install: it is a package that runs with your
agent's rights (postmark-mcp, 2025).

A block says what to do instead, so the agent can fix its own command: one version that fixes every blocking
advisory (`next@15.0.0` -> `next@15.5.28`, same major line when possible), or the closest real npm name for a
hallucinated one ("did you mean `react-dom`?").

Speed: answers are cached on disk (`~/.cache/skedaddle`, 0700; 10 min for registries and OSV). A repeat check takes
about 0.2 s; a first check is one round trip to the registries (about 2 s; 2.7 s for `next`, whose metadata is 31 MB).
An install without a version always reads today's `latest` live, so a cache never hides a release that just shipped.

`skedaddle-mcp stats` shows what it did for you: installs checked, blocked, asked, by kind. The log is local
(`~/.local/state/skedaddle/decisions.jsonl`, 0600, secrets redacted); nothing is sent anywhere.

### As an MCP server (any MCP client)

```bash
claude mcp add skedaddle -- skedaddle-mcp
```

Tools: `check_package(ecosystem, package)` and `audit_lockfile(path)`.

### From a shell or CI

```bash
skedaddle-mcp check pypi requests==2.32.3
skedaddle-mcp audit package-lock.json      # also npm-shrinkwrap.json, requirements*.txt
skedaddle-mcp doctor                       # which package-manager protections are off, and the lines to add
```

Exit codes: 0 allow, 1 warn, 2 block, 3 could not verify.

## For teams: mirrors, internal packages, exceptions

Commit a `.skedaddle.toml` at the repo root (or use `~/.config/skedaddle/config.toml` for yourself):

```toml
trusted_registries = ["https://artifactory.corp.example/api/npm/"]  # your mirror: no longer "unverifiable",
                                                                    # packages are still checked by name
internal_scopes = ["@corp"]   # your npm scopes
internal_names  = ["corp-*"]  # internal names in any ecosystem

[[allow]]                     # a reviewed exception, always with an end date
package = "npm:left-pad@1.3.0"
reason  = "SEC-123: vendored fork, reviewed"
expires = "2026-12-31"
```

- **Dependency confusion.** An internal name that *exists* on the public registry is blocked: a resolver that falls
  back to the public registry would install the attacker's package (Alex Birsan, 2021: Apple, Microsoft, Netflix,
  PayPal and 30+ others). An internal name that is absent publicly is fine, not "hallucinated".
- **The repo file is not trusted until you trust it.** A `.skedaddle.toml` can arrive in a malicious pull request or
  be written by the agent itself, and it only relaxes checks. It applies after you run `skedaddle-mcp trust`, which
  records the hash of exactly that content; any edit voids it. The hook asks you whenever a command runs `trust`,
  writes skedaddle's policy or state files, or sets `SKEDADDLE_*`. The hook sees shell commands only, so also deny
  the agent's file tools on these paths in `~/.claude/settings.json` (an `Edit` rule covers Write and Edit, and Claude
  Code also applies it to `sed`/`tee`/redirections; a `Write(...)` rule would not match anything):
  `"permissions": {"deny": ["Edit(**/.skedaddle.toml)", "Edit(~/.config/skedaddle/**)", "Edit(~/.local/state/skedaddle/**)"]}`

## Signals

| Signal | Severity | Ecosystems | What it means |
|---|---|---|---|
| `not-found` | block | all | the name does not exist (hallucinated / typo) |
| `malware`, `security-placeholder` | block | all / npm | OSV `MAL-*` or a malware advisory; npm replaced the package with a `-security` placeholder |
| `unpublished-version`, `yanked` | block | npm / PyPI, crates | the version was pulled after publication |
| `provenance-lost` | block | npm, PyPI | earlier releases had a provenance attestation (npm) or PEP 740 attestation (PyPI); this one does not |
| `install-script-added` | block | npm | a `preinstall`/`install`/`postinstall` script appears that the previous release did not have |
| `cve` | block | all | HIGH/CRITICAL in this exact version **and** a fixed version exists (`SKEDADDLE_ALL_CVES=1` reports the rest as info) |
| `fresh-package` | block | all | the package itself is under 30 days old |
| `dependency-confusion` | block | all | one of your internal names exists on the public registry |
| `new-publisher` | warn | npm, PyPI | a release under 90 days old, by an account / trusted publisher that published none of the recent releases, without provenance (info on a major bump or an older release) |
| `deps-added-in-patch`, `no-git-head` | warn | npm | a patch release adds dependencies; not published from a git checkout |
| `fresh-release` | info (warn next to another signal) | all | the version is under 3 days old |
| `low-downloads` | warn | npm | under 50 downloads last week |

## What leaves your machine

Only package names and versions, sent to the public registries (`registry.npmjs.org`, `api.npmjs.org`, `pypi.org`,
`crates.io`) and to [OSV](https://osv.dev) (`api.osv.dev`). Nothing else, no telemetry.

## How it compares (credit where due)

Most of this problem is solved by settings you should turn on anyway; `skedaddle-mcp doctor` shows which are off:
npm `min-release-age`, `ignore-scripts`; pnpm `minimumReleaseAge`, `trustPolicy: no-downgrade`, `strictDepBuilds`;
uv `exclude-newer`. A cooldown alone would have stopped the axios and litellm releases.

| Tool | Overlap | Difference |
|---|---|---|
| [npq](https://github.com/lirantal/npq) (Apache-2.0) | provenance regression, new maintainer, install scripts (npm) | skedaddle adds PyPI/crates, the agent hook and MCP |
| [pnpm](https://pnpm.io/settings/dependency-resolution) settings | cooldown, trust downgrade, build scripts | only when pnpm is the package manager and configured |
| [Aikido safe-chain](https://github.com/AikidoSec/safe-chain), [Socket sfw](https://github.com/SocketDev/sfw-free) | malware gating as an install wrapper, no account | different licences; skedaddle adds release-integrity signals |
| [Socket MCP](https://github.com/SocketDev/socket-mcp) | package scores over MCP | needs a Socket sign-in per call |

## Scope

skedaddle answers one question: *is what the agent is about to install safe?* Packages and MCP servers, from
registries, mirrors and lockfiles. It deliberately does not police the rest of what an agent does (editing its own
settings or hooks, permission-bypass flags, destructive or exfiltrating commands). Those are real and documented
(CVE-2025-53773, CVE-2025-54135/54136, the Nx "s1ngularity" malware launching AI CLIs with bypass flags) and belong in
a separate, focused guard rather than in this tool.

## Threat model

skedaddle catches the mistakes of a **cooperative agent using ordinary commands**: a hallucinated name, a pinned
version that was compromised, a lockfile edit, a git or custom-registry source it did not notice. It is not a sandbox:
an agent (or a prompt injection) that deliberately hides an install — a script file, `eval`, base64, a binary that
fetches packages — is out of scope. For that, run installs without network access or in a container.

## Limitations

- A custom registry in your *global* `~/.npmrc` or `pip.conf` is not detected (a project `.npmrc` is): the checks run
  against the public registries.

- No tarball-vs-source diff yet (the xz-utils class); `no-git-head` is a weak proxy.
- Typosquats that sit quietly for months, and long-con maintainers, pass the integrity signals; only OSV catches them
  once reported.
- The hook understands: `npm|pnpm|yarn|bun install/add/i/it/ci`, `npm exec|x|create|init`, `npx`, `pnpm|yarn dlx`,
  `bun x`, `bunx`; `pip`/`pipX.Y`/`python -m pip install`, `uv add`, `uv pip install|sync`, `uv tool install`,
  `uv run --with`, `uvx`, `pipx install|run|inject`, `poetry add`; `cargo add|install`. Also through `cd`, `sh -c`,
  `env`, `sudo`, `nice`, `timeout`. Not yet: `uv sync` / `poetry install` from `pyproject.toml`, pnpm/yarn/bun
  lockfile diffs (only `package-lock.json` is diffed against git HEAD). A script that installs packages by other
  means is not seen.
- Thresholds (30-day package age, 3-day release age, 50 downloads) are judgement calls; open an issue with data.

## Development

```bash
uv sync
uv run pytest            # offline: recorded registry/OSV answers in tests/fixtures
uv run ruff check src tests
uv run python tests/record_fixtures.py   # re-record fixtures (network)
```

Tests cover real incidents from recorded registry data (event-stream, axios 1.14.1, ua-parser-js, crossenv,
hallucinated names), honest packages (no false alarms), and synthetic versions of incident patterns whose malicious
releases are no longer in the registry.

## License

Apache-2.0. See [LICENSE](LICENSE).
