# pm

Path-keyed password manager in Rust. Secrets live under `PM_DATA`, encrypted with a
master key sealed in the macOS Keychain. Secret ops are gated by Touch ID, with a
short unlocked session so you are not prompted every command. Each write is committed
into the git repo inside `PM_DATA`.

## Requirements

- macOS with Touch ID (or device password fallback)
- Rust toolchain
- `git` on `PATH`

## Build

```bash
cargo build --release
# binary: target/release/pm
```

## Setup

```bash
export PM_DATA="$HOME/.local/share/pm"
pm init
```

`init` creates `keys.db`, a git repo, and a Keychain-backed master key (Touch ID prompt).

## Session cache

After a successful Touch ID unlock, the session is cached in `$PM_DATA/.session`
(mode `0600`) for a sliding TTL (default **180s** / 3 minutes), capped by a hard limit
from the unlock (default **900s** / 15 minutes).

With a local ssh-agent (`SSH_AUTH_SOCK`, always set on macOS), the file holds only the
master key **encrypted** with a key derived from an agent signature. The signing key is a
throwaway ed25519 key that exists only in the agent, added with the hard limit as its
agent lifetime. A copy of the file is useless on its own, and the session ends when the
agent drops the key (lifetime, `pm lock`, `ssh-add -D`, logout). Without a usable agent
(none running, an agent that refuses keys like 1Password's, or inside an SSH login where
the agent is forwarded), pm warns and stores the master key in the file in plaintext.

This protects against the file leaking (backups, disk access, copies). It does **not**
protect against other programs running as you while unlocked: they can ask the agent too.

```bash
# configure TTL (seconds); 0 = Touch ID every time
export PM_SESSION_TTL=180
pm --session-ttl 300 get /env/dev/url   # per-invocation override
# hard limit (seconds) from the Touch ID unlock; 0 = no limit
export PM_SESSION_MAX=900

pm unlock    # Touch ID once, start/refresh session
pm status    # locked / unlocked (via ssh-agent or plaintext file) + remaining seconds
pm lock      # clear session now (and remove its key from the agent)
```

Each `get` / `set` / `inject` / `dump` / `rm` that hits a valid session extends the TTL
again, but never past the hard limit: after it, Touch ID is required no matter how often
the vault is used.

## Commands

```bash
# Store (stdin, or hidden prompt on a TTY)
echo -n 'https://example.com' | pm set /env/dev/url
# One pair of surrounding quotes is stripped on input ("x" → x, handy for .env pastes);
# --raw stores the value exactly as given. Reads always return the stored value unchanged.
echo -n '"quoted"' | pm set --raw /env/dev/literal

# Read
pm get /env/dev/url
pm get -o clipboard /env/dev/url   # hidden from clipboard managers, cleared after 45s
pm get -o clipboard --clear-after 10 /env/dev/url   # or PM_CLIPBOARD_CLEAR; 0 = never

# Inject matching keys as env vars, then run a command
# /env/dev/url → DEV_URL (keeps last prefix segment)
pm inject --prefix /env/dev -- env | grep DEV

# Override mask: /env/dev/url → URL
pm inject --prefix /env/dev --mask /env/dev -- printenv URL

pm list
pm list /env/dev
pm rm /env/dev/url
```

## Storage

```
$PM_DATA/           # mode 0700 (enforced on every command)
  .git/           # every set/rm is a commit
  keys.db         # SQLite: path → nonce + ciphertext
  .lock           # write lock (gitignored)
  .session        # unlocked master key cache (gitignored, 0600)
  .gitignore
```

Values are XChaCha20-Poly1305 with AAD = path. The master key is 32 random bytes
in the Keychain (`pm.master-key` / `pm:$PM_DATA`).

## Security notes

### Git history keeps every old value

Every `set` and `rm` commits a snapshot of `keys.db`, so `rm` and overwrites don't erase
anything from history: each value ever stored stays in `.git` as ciphertext, and commit
messages show paths in plaintext (`set /env/prod/stripe_key`). That's what makes undo
possible (`git -C "$PM_DATA" log`, then check out an older `keys.db`), but it also means:

- After rotating a leaked secret, the leaked value is still in history.
- If the master key is ever compromised, every value that ever existed can be decrypted.
- Anyone who can read the repo, or a remote you push it to, sees all path names.

(Inside `keys.db` itself, deleted and replaced values are zeroed.)

To wipe history and keep only the current state (this also removes undo):

```bash
cd "$PM_DATA"
old=$(git branch --show-current)
git checkout -q --orphan pm-fresh
git -c user.name=pm -c user.email=pm@local -c commit.gpgsign=false commit -qm "history reset"
git branch -D -q "$old" && git branch -m "$old"
git reflog expire --expire=now --all && git gc -q --prune=now
```

Copies elsewhere (pushed remotes, backups, Time Machine) are not affected.
