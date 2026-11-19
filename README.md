# agpass

A local secrets broker for AI coding agents on macOS. Agents (Claude Code) get
secrets over a Unix socket, scoped to the project they work on, without you at
the keyboard. You unlock once per server start; each Claude session gets the
folders of the repository it works in.

## The problem

Coding agents need credentials to do real work: database URLs for tests, API
keys for dev servers, tokens for deploys, SSH for `git push`. The usual ways
to hand them over all go wrong in the same direction:

- **`.env` files, shell variables, `~/.ssh`**: the agent sees everything you
  can, in every project, whether the task needs it or not.
- **Pasting into the chat**: the secret lands in the transcript, gets sent to
  the model provider and stays there.
- **Asking you each time** (prompts, Touch ID): useless when agents run on
  their own while you are away and the Mac is locked.
- **No record**: you can't tell afterwards which session used which secret.

Agents rarely leak secrets on purpose. They get confused: they grab another
project's credentials because they were nearby, print a token while
debugging, push with your personal SSH key because it was the default, or run
tests against production because that's the URL they found.

agpass gives agents one place to ask. A session gets the secrets of the
repository it works in, values come back redacted unless explicitly revealed,
anything beyond that needs a stated reason, and every access shows on a live
dashboard. It runs unattended once you have unlocked it.

## Threat model

**agpass is a guardrail for confused agents, not a defense against
malicious ones.** It keeps well-behaved agents on a narrow path and makes
what they do visible. An agent that sets out to steal secrets, running as
your user, can get around it (see [Known limits](#known-limits-v1)).

What it protects against:

| Risk | What agpass does |
|---|---|
| An agent uses another project's secrets | Sessions get only the folders linked to their repository. Anything else needs a reason, judged by an LLM gatekeeper against your folder descriptions. |
| Secrets end up in transcripts and logs | Values are redacted by default (`[REDACTED_AGPASS]`), including inside URLs and other fields. `--reveal` works but is logged as a warning. |
| An agent pushes or logs in with your personal SSH key | Agents use one agpass SSH key through agpass's SSH agent, only for hosts they are allowed. `agpass ssh command` ignores your `~/.ssh/config`. |
| An agent reads agpass's own keys | `SYSTEM` (the gatekeeper's OpenAI key, the SSH key) is never granted to a normal session. The SSH private key can't be read even by an admin session. |
| An agent gives itself more access | Admin access needs a one-time code that you mint with the master password (or Touch ID through 1Password). |
| Nobody notices what happened | Every request, grant and denial goes to an encrypted audit log, live on the `serve` dashboard. |
| Secrets at rest | The database is encrypted with a key wrapped by your master password (Argon2id). |
| Malware that copies your files | Nothing agpass holds is in plaintext on disk, and the socket answers only Claude's process tree. See [File-stealing malware](#file-stealing-malware). |

What it trusts: you, the agpass binary, the macOS kernel's process and code
signing information, and Claude Code's Anthropic signature. The gatekeeper
(OpenAI) sees folder names, descriptions and the agent's reason, never secret
values.

Out of scope: an agent determined to get around agpass. It runs as your user,
so it can read your files, edit `.git/config`, replace the agpass binary or
kill the server. Every such way out is listed under
[Known limits](#known-limits-v1).

### While you are away

agpass is built to run unattended, with the Mac locked. In that state, even a
capable agent has no simple way to get at the vault without going through
agpass's rules:

- **The files are useless without the master password.** `agpass.db` is
  encrypted (Adiantum) with a random key, and `agpass.key` wraps that key
  with the master password through Argon2id (128 MiB, 3 passes). A copied
  vault means an offline guessing attack on the master password, so use a
  strong one (at least 10 characters is enforced).
- **The master password isn't stored anywhere an agent can read.** You type
  it when `serve` starts, or 1Password supplies it behind Touch ID. agpass
  never runs `op` from inside an agent's process tree, so an agent can't
  start a 1Password prompt that would unlock 1Password in its own session.
- **The server's memory can't be read.** The binary runs with the hardened
  runtime: debuggers can't attach (`lldb -p` is refused, while it attaches
  to the same binary built without it), dylibs can't be injected, and core
  dumps are off. A program the agent compiles can't get the server's task
  port at all. This assumes the agent has no root (no passwordless `sudo`).
- **Admin access needs you.** Codes are minted only from your own
  terminal: the server refuses `mint` from a process running under Claude,
  even with the master password.

What an agent *can* still do is work within agpass's rules in ways they don't
foresee: the main one is editing `.git/config` to look like another
repository and get its folders. Those are listed under
[Known limits](#known-limits-v1), along with what takes effect only after
you come back (a replaced binary capturing the password at the next `serve`).

### File-stealing malware

Common infostealers are passive: they copy well-known files (`.env`,
`~/.aws/credentials`, `~/.ssh/id_*`, shell history, Claude Code transcripts)
and upload them. A secret kept in agpass instead isn't in any of them:

- the vault is encrypted, and copying it out leaves only an offline guessing
  attack on the master password;
- the agents' SSH key lives in the vault, not in `~/.ssh`;
- transcripts and logs hold `[REDACTED_AGPASS]`, not the value, unless an
  agent used `--reveal` and printed it;
- the socket gives no secrets to a process that isn't running under a
  signed Claude Code process and has no master password, so malware that
  asks agpass directly is refused.

This covers only secrets that live in agpass. Keys still in `~/.ssh`,
`.env` files you keep, and anything an agent revealed and wrote to a file are
as exposed as before. Malware that actively targets agpass (running itself
under Claude, or replacing the binary to catch the master password) is the
same out-of-scope case as a malicious agent.

## Compared to 1Password service accounts

A [service account](https://www.1password.dev/service-accounts/) is a bearer
token: whoever holds it gets its access. agpass has no token; it identifies
the calling Claude process and the repository it works in.

| | 1Password service account | agpass |
|---|---|---|
| **Who gets access** | Anyone with the token. An agent can read it, print it, or use it elsewhere. | No token: the server identifies the calling Claude process (kernel peer info, Anthropic code signature). A session lives as long as that process. |
| **Scope** | Fixed vaults per token; every agent with the token sees all of them, in every project. Per-project scope means one token per project, stored somewhere the agent can read. | Per session, from the repository it works in. Other folders need a stated reason, judged by the gatekeeper. |
| **Values in transcripts** | `op read` returns plaintext into the agent's context. | Redacted by default; `--reveal` is logged as a warning. |
| **Asking for more** | No: the token's scope is all there is. | `connect --folder` (gatekeeper), `connect --create` for a new repository, admin access through a code you mint. |
| **SSH** | Not part of service accounts. The 1Password SSH agent needs approval in the app and stops when 1Password locks. | A dedicated agent key, signed only for allowed, pinned hosts, unattended. |
| **Audit** | A usage report per service account: all agents look like one identity. | Per session (process, folder, repository), denials included, live on the dashboard. |
| **Unattended** | Yes | Yes, after one unlock |

Where 1Password is better: it is a mature, audited, synced store with
backups, recovery, central revocation and team sharing, and works in CI, on
servers and on any OS. agpass is a local v1 for macOS and Claude Code, running
as your user. 1Password's [Environments](https://www.1password.dev/security-for-ai)
(a `.env` mount, with an MCP server and a Claude Code plugin) scope secrets
per project without a token in the repository, but the agent still reads the
values. Neither stops a malicious agent: with a service account it copies the
token, with agpass it edits `.git/config` or uses your `~/.ssh`.

They combine: agpass can [read its master password from
1Password](#master-password-from-1password).

## Guide

### 1. Install

```sh
make install          # builds, signs with hardened runtime, installs to ~/.local/bin, links the skill
```

### 2. Set up

```sh
agpass setup
```

Interactive. Run it again any time to change something; it works with the
server running or stopped.

1. **Master password**: creates the vault, or unlocks it. It protects every
   secret and cannot be recovered.
2. **LLM gatekeeper** (optional): an OpenAI API key, checked online before it
   is saved. Without it, agents get only folders linked to their repository.
3. **SSH key for agents** (optional): creates the shared agent SSH key (see
   [step 7](#7-ssh-for-agents)).
4. **1Password** (optional): read the master password from 1Password instead
   of typing it (see [below](#master-password-from-1password)).

### 3. Run the server

```sh
agpass serve
```

In a terminal tab you keep open. It asks for the master password (or reads
it from 1Password), then shows the live event log. The dashboard is
view-only: `↑↓`/`j k` scroll, `g`/`G` top/bottom, `/` filter, `q` twice
stops the server. History is kept for 90 days.

### 4. Add folders and secrets

A folder holds the secrets of one project and is linked to its repositories.
Commands run outside an agent ask for the master password:

```sh
agpass folder create crm --project crm --desc "CRM app: Postgres, Stripe test keys" --repo github.com/acme/crm
agpass set crm/db url:url=postgres://app:...@db/crm password:password=-     # "-" prompts for the value
```

Write folder descriptions for the gatekeeper: they are what it judges an
agent's reason against.

A folder can be linked to several repositories. `folder edit` changes one
link at a time and leaves the others:

```sh
agpass folder edit crm --repo github.com/acme/crm-web        # link one more repository
agpass folder edit crm --rm-repo github.com/acme/crm-web     # unlink it
```

Repositories are stored as `host/owner/repo`, whatever form you give
(`git@github.com:acme/crm.git`, an https URL).

### 5. Let agents connect

Nothing to do per session. In a project, tell Claude *connect to agpass*, or
it does so on its own when it needs a secret (the skill tells it how). Each
Claude process gets a session with the folders linked to its repository. For
a new project, *connect to agpass and create a folder for this repo* makes a
folder linked to the repository, which the agent can then fill.

### 6. Admin access for one session

To let one Claude session manage everything (all folders and `SYSTEM`), mint
a code and give it to Claude:

```sh
agpass mint           # in your own terminal; prints agp-xxxx-xxxx (redeem within 10 minutes)
```

Claude runs `agpass elevate agp-xxxx-xxxx` and has admin access for 1 hour.
`mint` is refused when run from inside Claude (a `!` command included), so an
agent can't mint a code for itself.

### 7. SSH for agents

One shared SSH key, kept in the vault (`SYSTEM/ssh`), used by agents through
agpass's SSH agent:

```sh
agpass ssh keygen        # or: agpass ssh import ~/.ssh/some_key; or in agpass setup
agpass ssh key           # public key: add it on GitHub (ideally an account for agents) or servers
```

Agents run `agpass ssh allow --host github.com --reason "…"`, then
`GIT_SSH_COMMAND="$(agpass ssh command)" git push`. Their repository's host is
allowed automatically. Other hosts go to the gatekeeper, which is permissive
here: any concrete reason that fits the project passes, and it reads
agent-written folder descriptions as evidence of the project's servers. The
key only logs in where you installed its public key, so that is the real
limit.

- No session can read or replace the private key, not even an elevated one.
- The agent signs only after the ssh client proves which server it talks to
  (OpenSSH `session-bind@openssh.com`, verified with the server's host key)
  and only for hosts the session is allowed. Host keys are pinned from the
  network on first allow. Forwarded use is refused.
- `agpass ssh command` ignores `~/.ssh/config`, so your own `IdentityFile`
  entries can't slip in, and trusts only agpass's pinned `known_hosts`.
  Agents need real host names; your config's aliases don't apply.
- Pinned host keys are never replaced on their own. When a host really
  changed its keys (a rotation, a rebuilt server), agents get "Host key
  verification failed" until you run `agpass ssh unpin HOST` (master
  password; `HOST` as in `ssh allow`, e.g. `server:2222`). The next
  `ssh allow` for that host pins the keys it serves then.
- agpass sees the host, not the repository: a session allowed `github.com`
  can push wherever that key can. Scope the key on GitHub's side.

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

**agpass never runs `op` from inside an agent's process tree** (a process
under Claude, found the same way the server identifies agents). Approving a
1Password prompt an agent started would leave `op` unlocked in the agent's
session for a while (1Password's setting): the agent could then run
`op read` itself and get the master password, or anything else in your
1Password, without another prompt. So commands an agent runs that need the
master password fail with "run this in your own terminal", and
the server also refuses `mint` from a process under Claude. If you see a 1Password
prompt for `op` you didn't start, deny it.

## Instructions for agents

`make install` also links the Claude Code skill
[`.claude/skills/agpass`](.claude/skills/agpass/SKILL.md) into
`~/.claude/skills/agpass` (or run `make install-skill`). Claude loads it whenever
a task needs a credential. It covers connecting, requesting access, using
secrets without printing them, storing new ones, and SSH.

## How it works

- **Data**: `~/.local/share/agpass` (or `$XDG_DATA_HOME/agpass`, or `$AGPASS_DIR`).
- **Server**: `agpass serve`, HTTP over `agpass.sock` in the data directory (mode 0600). Without a terminal, `agpass serve --password-stdin` prints log lines instead of the dashboard. Only `agpass setup` creates a vault.
- **Storage**: SQLite encrypted with the Adiantum VFS ([ncruces/go-sqlite3](https://github.com/ncruces/go-sqlite3), no cgo). A random 32-byte key is wrapped by your master password (Argon2id, XChaCha20-Poly1305) in `agpass.key`.
- **Caller identity**: the server reads the socket peer pid, then walks up the parent processes to the nearest one running Anthropic-signed code: the kernel's hash of the running code (`csops`) must match a file at the kernel's executable path (`proc_pidpath`) that carries a valid Anthropic Developer ID signature. A session is bound to that Claude process's (pid, start time), so it ends when Claude exits.
- **Sessions**: every verified Claude process gets a session on its first request. What it can read depends on its grants, unless it redeemed an admin code (`agpass mint` → `agpass elevate`): then it can access every folder, `SYSTEM` included, for 1 hour. Codes are single use, valid for 10 minutes, and all are revoked after 10 invalid attempts.
- **Scoping**: `agpass connect` grants folders whose repos include the git remote of the Claude process's working directory, which the server reads itself. `connect --create` makes a folder for a repository that has none and grants it. Agents can link folders only to their own repository, and `folder edit` never replaces a folder's repository list: it links or unlinks one repository (for an agent, only its own). When a session has no folder at all, or asks for more with `connect --folder`, an LLM gatekeeper (OpenAI `gpt-6-luna`, reasoning effort low, structured output) decides from your folder descriptions and the agent's reason; folder text written by agents is marked untrusted. A session that already has its folders and connects again is not judged again. Folder names, projects, descriptions, repos and the agent's reason are sent to OpenAI with `store: false`. The key lives in `SYSTEM/openai` (`api_key`); an optional `model` field overrides the model. Sessions may edit folders they have, and they get folders they create. `SYSTEM` is never granted.
- **Redaction**: `password` and `sensitive` fields, URL credentials, credential query parameters, and secret values repeated inside other fields all become `[REDACTED_AGPASS]`. `--reveal` returns plaintext and is logged as a warning.
- **SSH agent**: `agent.sock` in the data directory. It offers the key only to sessions with an SSH grant (or admin access), and signs only an SSH `publickey` login whose session ID matches a verified `session-bind@openssh.com`, for a pinned host the session is allowed (any host for an admin session). Host keys are pinned on the first allow and replaced only after `agpass ssh unpin HOST`.
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
- **An agent can edit the agpass config file**: it can point 1Password at the wrong item or break the file; at a terminal you then type the password (and `agpass setup` replaces a broken file), but `serve` without a terminal won't start.
- **"Under Claude" is checked by process ancestry.** A process an agent detaches (e.g. double-forked, so its parent becomes `launchd`) no longer looks like it runs under Claude: it could run `agpass mint` and trigger a 1Password prompt. Deny `op` prompts you didn't start; approving one gives that process 1Password, including the master password, while `op` stays unlocked.

## License

MIT, see [LICENSE](LICENSE).
