---
name: agpass
description: Get secrets (passwords, API keys, tokens, database URLs, credentials) from agpass, the user's local secrets broker, and store new ones there. Use whenever a command, test, script or dev server needs a credential, instead of .env files, hardcoding or asking the user to paste it; when the user says "connect to agpass" or gives an agp-xxxx-xxxx code; or when an agpass command fails with "not connected", "no access to folder" or "server is not running".
---

# agpass: secrets for this agent session

`agpass` (in PATH; source ~/Developer/persn/AgPass) is a local server the user
runs in a terminal tab. It hands out secrets to agent sessions, scoped to the
project they work on. Every request is shown live on the user's screen.

## Connecting (once per Claude session)

1. Run `agpass whoami`. It shows the session and its folders, or why not:
   - **"not connected to agpass"**: ask the user to run `agpass mint` and give
     you the code. Then run `agpass connect agp-xxxx-xxxx`. Codes are single
     use and expire after 10 minutes. Don't guess or reuse codes.
   - **"server is not running"**: ask the user to start `agpass serve` in a
     terminal tab. Don't start it yourself: it needs the master password.
   - **"not running under a recognised agent"**: your command runs outside the
     Claude Code process tree (e.g. through another tool's daemon). Run it
     directly from the Bash tool.
2. From the project's repository, ask for access with an honest, specific reason:
   ```sh
   agpass request-access --reason "fixing the CRM login bug; integration tests need the dev Postgres"
   ```
   Folders linked to this repository are granted automatically. Others are
   decided by an LLM gatekeeper from your reason. Add `--folder NAME` for a
   folder you know you need.
3. **If a folder is denied**, tell the user which one and why you need it. Don't
   retry with reworded reasons to talk your way in. The user can link the
   folder to this repository: `agpass folder edit NAME --repo github.com/org/repo`.

The session belongs to this Claude process and ends when it exits. Never ask
the user for the master password, and never run `mint` yourself.

## Finding secrets

```sh
agpass list                  # your folders with item names and field keys; other folders by name only
agpass get crm/db            # one item; secret values shown as [REDACTED_AGPASS]
```

Redacted output is safe to read and quote. Use it to see what exists.

## Using a secret without printing it

Get the plaintext with `--reveal` only inside the command that needs it:

```sh
psql "$(agpass get crm/db --reveal --field url)" -c 'select 1'
DATABASE_URL="$(agpass get crm/db --reveal --field url)" npm test
agpass get crm/stripe --reveal --json | jq -r '.fields[] | select(.key=="secret_key") | .value' | some-tool --key-stdin
```

- `--field` without `--reveal` prints the redacted value. You need both.
- Every `--reveal` is logged as a warning on the user's dashboard. Reveal what
  the task needs, when it needs it, not "just to look".
- Each Bash call is a new shell. Fetch the value inline in the command that uses it.

**Never** let a revealed value reach your context, a file or git:
- don't `echo`/`cat`/`print` it, run with `set -x`, or reveal it in a bare
  `agpass get --reveal`;
- don't write it to `.env`, config files, scripts, test fixtures or commits. If
  a tool only reads credentials from a file, ask the user first;
- watch for tools that echo connection strings in errors or verbose output.
  Silence or filter them.

If a secret does end up in your output, tell the user so they can rotate it.

## Storing secrets

When the user gives you a credential, or you create one (a generated password,
a new API token), store it instead of keeping it in files:

```sh
agpass set crm/stripe secret_key:sensitive=- <<<"$VALUE"     # "-" reads the value from stdin
agpass set crm/db url:url=postgres://app:...@db/crm host=db.internal
agpass set crm/db --rm old_key
```

- Types: `password` and `sensitive` (always redacted), `url` (credentials in it
  redacted), `text` (default; shown as is). Give every secret a secret type.
- `set` adds or replaces the named fields and keeps the rest. Every change keeps
  the previous version.
- Values passed as arguments show up in the process list and in your
  transcript. For real secrets prefer `=-` with stdin.

A new project's folder: create it only when there is no folder for the project.
You get access to folders you create:
```sh
agpass folder create crm --project crm --desc "CRM app: dev Postgres, Stripe test keys" --repo github.com/acme/crm
```
Write the description for the user and the gatekeeper: what the secrets are and
which project uses them. Never put instructions or access policy in it.

## Reference

| Command | Notes |
|---|---|
| `agpass whoami [--json]` | session, repository, granted folders |
| `agpass request-access --reason R [--folder F] [--json]` | asks for folders; the repository is detected by the server |
| `agpass list [folder] [--json]` | no values |
| `agpass get folder/item [--field K] [--reveal] [--json]` | redacted unless `--reveal` |
| `agpass set folder/item key[:type]=value ... [--rm key]` | `value` of `-` reads stdin |
| `agpass folder create NAME --project P [--desc D] [--repo R]` | |
| `agpass folder edit NAME [--project P] [--desc D] [--repo R ...]` | only folders you have |

`SYSTEM` holds agpass's own keys and is never available to agents.
