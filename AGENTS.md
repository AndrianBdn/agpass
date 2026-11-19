# AGENTS.md

This file provides guidance to coding agents (Claude Code, Codex) when working with code in this repository.

agpass is a local secrets broker for AI coding agents on macOS: one Go binary that is both the server (`agpass serve`) and its CLI client, talking HTTP over a Unix socket. README.md has the problem statement, threat model and user guide; read its "Threat model" and "Known limits" before changing anything security-related.

## Commands

```sh
make build                      # go build + ad-hoc codesign with hardened runtime (-o runtime)
make install                    # build, install to ~/.local/bin, symlink the skill into ~/.claude/skills
make test                       # go vet + go test
go test -race ./...             # what to run before committing
go test -race -run TestKnownHostsConcurrentWrites ./internal/server/   # one test
gofmt -l .                      # must print nothing
```

- Some tests only run when the test process is under a Claude Code process (`peer` FindAgent, `server` SSH test with the real `/usr/bin/ssh`); elsewhere they `t.Skip`.
- Unix socket paths are limited to 104 bytes on macOS: tests that listen use `os.MkdirTemp("/tmp", "agp")`, not `t.TempDir()`.
- Try things against a throwaway vault: `AGPASS_DIR=/tmp/agpe2e` (the config file then also comes from `$AGPASS_DIR/config.toml`). Never touch the user's real vault in `~/.local/share/agpass` or call the real `op` (it prompts for Touch ID); tests replace `opCommand` with a fake script.
- `agpass setup` and the `serve` dashboard need a TTY; drive them with `script -q /dev/null …` and piped input (`stty rows/cols` inside for the dashboard).
- The user may have `agpass serve` running from `~/.local/bin`; check (`pgrep -fl "agpass serve"`, process start time vs. binary mtime) before saying which version is running.

## Architecture

Packages under `internal/`:

- **`cli`**: every command. Human commands get the master password from `masterPassword()` (1Password via `op` when `[onepassword]` is configured, but never from a process under an agent; else typed; `--manual` forces typing) and send it as `X-Agpass-Master`. Agent commands send nothing: the server identifies them.
- **`server`**: HTTP handlers (`handlers.go`), auth, sessions, SSH agent (`ssh.go`).
  - Each route has an auth mode: `authNone`, `authAdmin` (master password), or `authSession` (master password or a verified agent process).
  - The resulting `caller` is `admin` (master password), `elevated` (agent session that redeemed a minted code, for 1 hour), or a plain agent session. `c.full()` is admin-or-elevated.
- **`peer`** (darwin): who is calling.
  - `LOCAL_PEERPID` on the socket, then walk up parent processes to one whose running code (`csops` CDHash) matches an on-disk binary signed by Anthropic (team `Q6L2SF6YDW`).
  - Sessions are keyed by that Claude process's (pid, start time).
  - The process's cwd and `.git/config` origin give the session's repository (`server/repo.go`).
- **`store`**: SQLite encrypted with the Adiantum VFS (`ncruces/go-sqlite3`, no cgo).
  - Schema changes go through `migrate()` (`pragma_table_info` + `ALTER TABLE`), since existing vaults must keep opening.
  - A generation counter file detects rollback.
- **`vault`**: `agpass.key`, the DB key wrapped by the master password (Argon2id + XChaCha20-Poly1305).
- **`llm`**: the gatekeeper, called over raw HTTP (no SDK) to the OpenAI Responses API with `store:false` and a strict JSON schema.
  - It decides folder access (`Decide`) and SSH hosts (`DecideSSH`) when there is no repository match.
  - It is a guardrail against confusion only; the reason it judges is written by the agent.
- **`redact`**: secret values become `[REDACTED_AGPASS]` everywhere, including inside URLs and other fields, unless `--reveal`.
- **`events`**: the audit log, stored in the DB and fanned out live to subscribers.
  - Agent-written text must go through `events.Clean`/`Format` before reaching a terminal.
  - Never log secret values.
- **`dashboard`**: the `serve` UI in raw terminal mode with plain ANSI.
  - It is deliberately not Bubble Tea or another TUI framework: those query the terminal at init, which stalled every CLI command.
  - It is view-only, because agents can type into terminals.
  - `serve` sends the standard `log` output to `io.Discard`, so library output can't corrupt the screen.
- **`sshagent`**: SSH pieces with no server dependency. The agent signs only an SSH `publickey` userauth request that:
  - has a session ID matching a verified `session-bind@openssh.com`;
  - is for a host the session is allowed and that agpass has pinned.

  Forwarding is refused. `agpass ssh command` uses `-F /dev/null` so the user's own keys in `~/.ssh/config` are never offered.
- **`config`**: optional TOML at `~/.config/agpass/config.toml`. Unknown keys are an error.

Access flow for `connect`:
1. Folders whose repos match the session's repository.
2. `--create` makes and grants a folder for a repository that has none.
3. Otherwise the LLM gatekeeper decides.

Invariants:
- `mint` is refused for a requester running under an agent, even with the master password (`agentAncestor` in the server and in the CLI).
- Agents may only link folders to their own repository, and unlink only their own. `folder edit` never replaces a folder's repository list (`add_repos`/`remove_repos`), so one session can't drop another project's link.
- The gatekeeper judges folder access only for a session with no folder at all, or for folders it asks for by name (`connect --folder`); connecting again must not widen access.
- Pinned SSH host keys are replaced only by the human (`ssh unpin`, master password), never by a session.
- `SYSTEM` (gatekeeper key in `SYSTEM/openai`, SSH key in `SYSTEM/ssh`) is never granted to a plain session.
- `SYSTEM/ssh` can't be read or replaced even by an elevated session, only with the master password (`sshKeyGuard`).

## Keeping things in sync

A CLI change usually touches four places: the `usage` string in `internal/cli/cli.go` (plus `sshUsage` in `ssh.go`), `README.md`, and the agent-facing skill at `.claude/skills/agpass/SKILL.md`. The skill is symlinked into `~/.claude/skills`, so edits there are live for every Claude session on this Mac. `api.Version` is the version; the client warns when it differs from the server's.

## Threat model in one line

agpass is a guardrail for confused agents, not a defense against malicious ones: everything runs as the user. Don't claim protections it doesn't have. Don't open new paths for an agent to get a secret, the master password, or admin access without the user. Known holes (e.g. the repository comes from an agent-editable `.git/config`) are listed in README "Known limits".
