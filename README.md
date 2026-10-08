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

After a successful Touch ID unlock, the master key is cached in `$PM_DATA/.session`
(mode `0600`) for a sliding TTL (default **180s** / 3 minutes).

```bash
# configure TTL (seconds); 0 = Touch ID every time
export PM_SESSION_TTL=180
pm --session-ttl 300 get /env/dev/url   # per-invocation override

pm unlock    # Touch ID once, start/refresh session
pm status    # locked / unlocked + remaining seconds
pm lock      # clear session now
```

Each `get` / `set` / `inject` / `rm` that hits a valid session extends the TTL again.

## Commands

```bash
# Store (stdin, or hidden prompt on a TTY)
echo -n 'https://example.com' | pm set /env/dev/url
# One pair of surrounding quotes is stripped on input ("x" → x, handy for .env pastes);
# --raw stores the value exactly as given. Reads always return the stored value unchanged.
echo -n '"quoted"' | pm set --raw /env/dev/literal

# Read
pm get /env/dev/url
pm get -o clipboard /env/dev/url

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
$PM_DATA/
  .git/           # every set/rm is a commit
  keys.db         # SQLite: path → nonce + ciphertext
  .lock           # write lock (gitignored)
  .session        # unlocked master key cache (gitignored, 0600)
  .gitignore
```

Values are XChaCha20-Poly1305 with AAD = path. The master key is 32 random bytes
in the Keychain (`pm.master-key` / `pm:$PM_DATA`).
