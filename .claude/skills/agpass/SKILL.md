---
name: agpass
description: Get secrets (passwords, API keys, tokens, database URLs, credentials) from agpass, the user's local secrets broker, and store new ones there. Use whenever a command, test, script or dev server needs a credential, instead of .env files, hardcoding or asking the user to paste it; when the user says "connect to agpass", asks to set up secrets for a project, or gives an agp-xxxx-xxxx admin code; or when an agpass command fails with "no access to folder" or "server is not running".
---

# agpass: secrets for this agent session

`agpass` (in PATH; source ~/Developer/persn/AgPass) is a local server the user
runs in a terminal tab. It hands out secrets to agent sessions, scoped to the
project they work on. Every request is shown live on the user's screen.

## Connecting (once per Claude session)

There are no codes: every Claude process gets its own session automatically.
What it may read depends on the repository it runs in.

1. From the project's repository, connect with an honest, specific reason:
   ```sh
   agpass connect --reason "fixing the CRM login bug; integration tests need the dev Postgres"
   ```
   agpass reads your working directory and its git `origin` itself. Folders
   linked to that repository are granted. Other folders are decided by an LLM
   gatekeeper from your reason; add `--folder NAME` for one you know you need.
2. **No folder for this repository yet** (new project, first setup): create
   one and get it in the same step:
   ```sh
   agpass connect --reason "first setup of acme/crm secrets" --create --desc "CRM app: dev Postgres, Stripe test keys"
   ```
   The folder is named after the repository (`--name` to choose) and linked to
   it, so later sessions in this repository get it automatically. Do this only
   when the user wants secrets for this project, and only when none exists.
3. **If a folder is denied**, tell the user which one and why you need it. Don't
   retry with reworded reasons to talk your way in. The user can link it to this
   repository: `agpass folder edit NAME --repo github.com/org/repo`.
4. **"server is not running"**: ask the user to start `agpass serve` in a
   terminal tab. Don't start it yourself: it needs the master password.
   **"not running under a recognised agent"**: your command runs outside the
   Claude Code process tree. Run it directly from the Bash tool.

`agpass whoami` shows the session, its repository and folders. Never ask the
user for the master password.

## Admin access (only with a code from the user)

When the user wants you to manage agpass itself (all folders, other projects'
secrets, the `SYSTEM` folder with the gatekeeper's OpenAI key), they run
`agpass mint` and give you a code:

```sh
agpass elevate agp-xxxx-xxxx
```

This session then has access to everything for 1 hour (or until this Claude
process exits). Use it only for what the user asked; every action is shown on
their dashboard tagged `[admin]`. Never ask for a code to get around a denied
folder: explain the denial instead and let the user decide.

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

A project's first folder comes from `connect --create` (above). For an extra
folder in the same project: `agpass folder create NAME --project P --desc D`.
Folders you create are linked to your own repository only; agpass refuses
other repositories. Write descriptions for the user and the gatekeeper: what
the secrets are and which project uses them. Never put instructions or access
policy in them.

## Reference

| Command | Notes |
|---|---|
| `agpass whoami [--json]` | session, repository, granted folders, admin expiry |
| `agpass elevate CODE` | admin access for 1 hour, with a code the user minted |
| `agpass connect --reason R [--folder F] [--create [--name N] [--desc D]] [--json]` | get this repository's folders; `--create` makes one if none |
| `agpass list [folder] [--json]` | no values |
| `agpass get folder/item [--field K] [--reveal] [--json]` | redacted unless `--reveal` |
| `agpass set folder/item key[:type]=value ... [--rm key]` | `value` of `-` reads stdin |
| `agpass folder create NAME --project P [--desc D]` | linked to your repository |
| `agpass folder edit NAME [--project P] [--desc D]` | only folders you have |

`SYSTEM` holds agpass's own keys and is never available to agents.
