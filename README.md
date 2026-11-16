# agpass

A local secrets broker for AI coding agents on macOS. Agents (Claude Code) get
secrets over a Unix socket, scoped to the project they work on, without you at
the keyboard. You unlock once per server start and approve each agent session
with a one-time code.

## Install

```sh
make install          # builds, signs with hardened runtime, installs to ~/.local/bin
```

## Use

```sh
agpass serve          # in a terminal tab: asks for the master password, then shows the live event log
```

The first run creates the vault and asks for a new master password twice.
The dashboard is view-only: `↑↓`/`j k` scroll, `g`/`G` top/bottom, `/` filter,
`q` twice stops the server. History is kept for 90 days.

Set up folders and secrets yourself (any command run outside an agent asks for
the master password):

```sh
agpass folder create crm --project crm --desc "CRM app: Postgres, Stripe test keys" --repo github.com/acme/crm
agpass set crm/db url:url=postgres://app:...@db/crm password:password=-     # "-" prompts for the value
agpass set SYSTEM/anthropic api_key:sensitive=-                            # enables the LLM gatekeeper
```

Connect an agent session:

```sh
agpass mint           # prints a one-time code, e.g. agp-k7m2-x9qd
```

Then tell Claude: *connect to agpass with `agpass connect agp-k7m2-x9qd`*.

## Instructions for agents

Paste into `~/.claude/CLAUDE.md`:

```markdown
## Secrets: agpass
Secrets live in agpass, not in .env files. Run `agpass help` for commands.
- If agpass says the session is not connected, ask the user to run `agpass mint` and give you the code, then `agpass connect <code>`.
- Before using secrets, run `agpass request-access --reason "<what you are working on and why>"` from the repo.
- `agpass get folder/item` shows values redacted. To use a value, pipe it without printing:
  `psql "$(agpass get crm/db --reveal --field url)"`, or `agpass get crm/db --reveal --json | jq ...`.
- Never print, log or commit revealed values.
```

## How it works

- **Data**: `~/.local/share/agpass` (or `$XDG_DATA_HOME/agpass`, or `$AGPASS_DIR`).
- **Server**: `agpass serve`, HTTP over `agpass.sock` in the data directory (mode 0600). Without a terminal, `agpass serve --password-stdin` prints log lines instead of the dashboard; it can't create a vault.
- **Storage**: SQLite encrypted with the Adiantum VFS ([ncruces/go-sqlite3](https://github.com/ncruces/go-sqlite3), no cgo). A random 32-byte key is wrapped by your master password (Argon2id, XChaCha20-Poly1305) in `agpass.key`.
- **Caller identity**: the server reads the socket peer pid, then walks up the parent processes to the nearest one running Anthropic-signed code: the kernel's hash of the running code (`csops`) must match a file at the kernel's executable path (`proc_pidpath`) that carries a valid Anthropic Developer ID signature. A session is bound to that Claude process's (pid, start time), so it ends when Claude exits.
- **Sessions**: `agpass mint` (master password) creates a single-use code that is valid for 10 minutes. `agpass connect <code>` binds the calling Claude process.
- **Scoping**: `request-access` grants folders whose `--repo` matches the git remote of the Claude process's working directory, which the server reads itself. Otherwise Claude Opus 5.5 decides from your folder descriptions and the agent's reason, using server-side refusal fallbacks; folder text written by agents is marked untrusted. Sessions may edit folders they have, and they get folders they create. `SYSTEM` is never granted.
- **Redaction**: `password` and `sensitive` fields, URL credentials, credential query parameters, and secret values repeated inside other fields all become `[REDACTED_AGPASS]`. `--reveal` returns plaintext and is logged as a warning.
- **Audit**: every request is logged in the encrypted database and shown on the `serve` dashboard. Values are never logged; agent-written text is shown with control characters escaped.
- **Rollback check**: every write bumps a generation counter. `serve` refuses a database older than the last one it saw.

## Known limits (v1)

Everything runs as your user. That's deliberate for v1, and it means:

- **An agent could replace the binary** in `~/.local/bin` to capture the master password on the next `serve`. Moving to `sudo install -o root` closes this.
- **An agent can kill the server, or delete or corrupt the database.** Keep backups of `~/.local/share/agpass/agpass.db` and `agpass.key`.
- **An agent can lock you out for 5 minutes** by sending 5 wrong master passwords.
- **A session covers everything Claude runs**, including test runners and package scripts.
- **The LLM gatekeeper guards against confusion, not malice.** The reason it judges is written by the agent.
