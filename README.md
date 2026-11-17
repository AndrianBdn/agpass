# agpass

A local secrets broker for AI coding agents on macOS. Agents (Claude Code) get
secrets over a Unix socket, scoped to the project they work on, without you at
the keyboard. You unlock once per server start; each Claude session gets the
folders of the repository it works in.

## Install

```sh
make install          # builds, signs with hardened runtime, installs to ~/.local/bin, links the skill
```

## Use

```sh
agpass setup          # once: creates the vault (master password); optional: OpenAI key for the gatekeeper, SSH key, 1Password
agpass serve          # in a terminal tab: asks for the master password, then shows the live event log
```

`agpass setup` checks the OpenAI key online before saving it. Run it again any
time to replace the key; it works with the server running or stopped.
The dashboard is view-only: `↑↓`/`j k` scroll, `g`/`G` top/bottom, `/` filter,
`q` twice stops the server. History is kept for 90 days.

### Master password from 1Password

agpass can read the master password with the 1Password CLI (`op`) instead of
asking: `serve`, `setup`, `mint`, `ssh keygen`/`import` and any command run
with `--admin`. Set it up with `agpass setup` (step 4): it asks for the
1Password account and item, checks that the item unlocks this vault, and
saves the config. Running setup again re-checks it. Or write it yourself in
`~/.config/agpass/config.toml`
(`$XDG_CONFIG_HOME/agpass/config.toml`, or `config.toml` in `$AGPASS_DIR`
when that is set):

```toml
[onepassword]
master_password = "op://Private/AgPass/password"  # secret reference, or an item name/ID (its "password" field)
account = "my.1password.com"                      # optional: which account, if op is signed in to several
```

`op` asks you to approve (Touch ID with the desktop app integration). If it
fails or the password is wrong, the command asks you to type it (or fails
without a terminal). `--manual` on any command skips 1Password. With
1Password configured, `serve` also starts without a terminal (log lines
instead of the dashboard).

An agent that runs `agpass mint` also triggers the 1Password prompt: approve
only what you started. Once approved, `op` may stay unlocked for that
terminal session for a while (1Password's setting), so later requests from
the same place may not prompt again; every mint shows on the dashboard.

Set up folders and secrets yourself (any command run outside an agent asks for
the master password):

```sh
agpass folder create crm --project crm --desc "CRM app: Postgres, Stripe test keys" --repo github.com/acme/crm
agpass set crm/db url:url=postgres://app:...@db/crm password:password=-     # "-" prompts for the value
```

Agents connect on their own: in a project, tell Claude *connect to agpass*
(or it does so when it needs a secret). For a new project, *connect to agpass
and create a folder for this repo* makes a folder linked to the repository.

To let one Claude session manage everything (all folders and `SYSTEM`), mint
an admin code and give it to Claude:

```sh
agpass mint           # master password; prints agp-xxxx-xxxx (redeem within 10 minutes)
```

Claude runs `agpass elevate agp-xxxx-xxxx` and has admin access for 1 hour.

## SSH key for agents

One shared SSH key, kept in the vault (`SYSTEM/ssh`), used by agents through
agpass's SSH agent:

```sh
agpass ssh keygen        # or: agpass ssh import ~/.ssh/some_key; or in agpass setup
agpass ssh key           # public key: add it on GitHub (ideally an account for agents) or servers
```

Agents run `agpass ssh allow --host github.com --reason "…"` (automatic for
their repository's host; other hosts go to the gatekeeper), then
`GIT_SSH_COMMAND="$(agpass ssh command)" git push`.

- No session can read or replace the private key, not even an elevated one.
- The agent signs only after the ssh client proves which server it talks to
  (OpenSSH `session-bind@openssh.com`, verified with the server's host key)
  and only for hosts the session is allowed. Host keys are pinned from the
  network on first allow. Forwarded use is refused.
- `agpass ssh command` ignores `~/.ssh/config`, so your own `IdentityFile`
  entries can't slip in, and trusts only agpass's pinned `known_hosts`.
- agpass sees the host, not the repository: a session allowed `github.com`
  can push wherever that key can. Scope the key on GitHub's side.

## Instructions for agents

`make install` also links the Claude Code skill
[`.claude/skills/agpass`](.claude/skills/agpass/SKILL.md) into
`~/.claude/skills/agpass` (or run `make install-skill`). Claude loads it whenever
a task needs a credential. It covers connecting, requesting access, using
secrets without printing them, and storing new ones.

## How it works

- **Data**: `~/.local/share/agpass` (or `$XDG_DATA_HOME/agpass`, or `$AGPASS_DIR`).
- **Server**: `agpass serve`, HTTP over `agpass.sock` in the data directory (mode 0600). Without a terminal, `agpass serve --password-stdin` prints log lines instead of the dashboard. Only `agpass setup` creates a vault.
- **Storage**: SQLite encrypted with the Adiantum VFS ([ncruces/go-sqlite3](https://github.com/ncruces/go-sqlite3), no cgo). A random 32-byte key is wrapped by your master password (Argon2id, XChaCha20-Poly1305) in `agpass.key`.
- **Caller identity**: the server reads the socket peer pid, then walks up the parent processes to the nearest one running Anthropic-signed code: the kernel's hash of the running code (`csops`) must match a file at the kernel's executable path (`proc_pidpath`) that carries a valid Anthropic Developer ID signature. A session is bound to that Claude process's (pid, start time), so it ends when Claude exits.
- **Sessions**: every verified Claude process gets a session on its first request. What it can read depends on its grants, unless it redeemed an admin code (`agpass mint` → `agpass elevate`): then it can access every folder, `SYSTEM` included, for 1 hour. Codes are single use, valid for 10 minutes, and all are revoked after 10 invalid attempts.
- **Scoping**: `agpass connect` grants folders whose repos include the git remote of the Claude process's working directory, which the server reads itself. `connect --create` makes a folder for a repository that has none and grants it. Agents can link folders only to their own repository. Otherwise an LLM gatekeeper (OpenAI `gpt-6-luna`, reasoning effort low, structured output) decides from your folder descriptions and the agent's reason; folder text written by agents is marked untrusted. Folder names, projects, descriptions, repos and the agent's reason are sent to OpenAI with `store: false`. The key lives in `SYSTEM/openai` (`api_key`); an optional `model` field overrides the model. Sessions may edit folders they have, and they get folders they create. `SYSTEM` is never granted.
- **Redaction**: `password` and `sensitive` fields, URL credentials, credential query parameters, and secret values repeated inside other fields all become `[REDACTED_AGPASS]`. `--reveal` returns plaintext and is logged as a warning.
- **Audit**: every request is logged in the encrypted database and shown on the `serve` dashboard. Values are never logged; agent-written text is shown with control characters escaped.
- **Rollback check**: every write bumps a generation counter. `serve` refuses a database older than the last one it saw.

## Known limits (v1)

Everything runs as your user. That's deliberate for v1, and it means:

- **An agent could replace the binary** in `~/.local/bin` to capture the master password on the next `serve`. Moving to `sudo install -o root` closes this.
- **An agent can kill the server, or delete or corrupt the database.** Keep backups of `~/.local/share/agpass/agpass.db` and `agpass.key`.
- **An agent can lock you out for 5 minutes** by sending 5 wrong master passwords.
- **A session covers everything Claude runs**, including test runners and package scripts.
- **Any Claude process on this Mac can connect**, without your approval, and gets the folders linked to the repository it runs in.
- **Your own SSH keys stay readable to agents** (`~/.ssh`, your ssh-agent): the agpass agent keeps well-behaved agents on the agpass key, it doesn't hide yours.
- **The repository comes from `.git/config`**, which an agent can edit: setting another project's `origin` would get that project's folders. Fine against confusion, not against a determined agent.
- **The LLM gatekeeper guards against confusion, not malice.** The reason it judges is written by the agent.
