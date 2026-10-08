# pm — project memory

Complete reference for humans and future agents. Captures intent, decisions, what shipped, and what was proposed but not built.

Last updated: 2026-08-19

---

## Purpose

`pm` is a **macOS CLI password / secrets manager** written in Rust.

- Secrets are addressed by **path-like keys** (e.g. `/env/dev/url`).
- Data lives under **`PM_DATA`** (required env var).
- Encryption is gated by **Touch ID** (device password fallback).
- A short **session cache** avoids prompting on every command.
- **`$PM_DATA` is a git repo**; every mutating write is a commit.

Original product brief: root `README.md` (also kept as user-facing usage docs).

---

## Quick start (current)

```bash
cargo build --release
export PM_DATA="$HOME/.local/share/pm"
./target/release/pm init
echo -n 'https://example.com' | ./target/release/pm set /env/dev/url
./target/release/pm get /env/dev/url
./target/release/pm inject --prefix /env/dev -- printenv DEV_URL
./target/release/pm inject --prefix /env/dev --mask /env/dev -- printenv URL
./target/release/pm unlock|status|lock
```

Binary: `target/release/pm` (crate name `pm`, edition 2021).

---

## Implemented CLI

| Command | Behavior |
|---------|----------|
| `pm init` | Create dir, SQLite DB, Keychain master key, git repo, Touch ID confirm |
| `pm set <path>` | Value from stdin, or hidden TTY prompt; encrypt + upsert + git commit |
| `pm get [-o stdout\|clipboard] <path>` | Decrypt; default stdout; optional clipboard |
| `pm inject [--prefix <prefix>] [--mask <prefix>] -- <cmd>…` | Decrypt all keys under prefix; inject as env; run command. Without `--mask`, keeps last prefix segment. |
| `pm dump [--prefix <prefix>] [--mask <prefix>]` | Decrypt matching keys; print `NAME='value'` (dotenv, single-quoted). Values with `'` or a line break are refused. Same naming as inject. |
| `pm list [--prefix <prefix>] [path]` | List paths, or env names that `--prefix` would inject |
| `pm rm <path>` | Delete + git commit (Touch ID / session) |
| `pm unlock` | Touch ID → write session cache |
| `pm lock` | Clear session cache |
| `pm status` | Locked / unlocked + remaining seconds |

**Global option**

- `--session-ttl <secs>` (also `PM_SESSION_TTL`), default **180**, `0` = no cache
- `--session-max <secs>` (also `PM_SESSION_MAX`), default **900**, `0` = no hard limit

**Env**

| Var | Meaning |
|-----|---------|
| `PM_DATA` | Vault directory (required) |
| `PM_SESSION_TTL` | Session TTL seconds (default 180) |
| `PM_SESSION_MAX` | Hard session limit seconds from unlock (default 900, `0` = none) |

---

## Path → env mapping (`inject` / `dump`)

| Path | No prefix (full path) | `--prefix /env/dev` (keep last segment) | `--mask /env/dev` |
|------|------------------------|------------------------------------------|-------------------|
| `/env/dev/url` | `ENV_DEV_URL` | `DEV_URL` | `URL` |

Rules (see `src/pathutil.rs`):

- Paths must start with `/`, no `.` / `..`, normalized (collapse empty segments).
- Strip leading `/`, optionally strip mask + `/`, replace `/` with `_`, uppercase.
- When `--prefix` is set and `--mask` is omitted, env names keep the last prefix segment (`--prefix /a/b` → `/a/b/c` maps to `B_C`).
- Within segments, `-` and `.` become `_` (so `/gather/bot-ox/secret` → `BOT_OX_SECRET`).
- Reject empty or invalid env names after masking.
- Reject two paths mapping to the same name (`/a/b-c` and `/a/b/c` → `A_B_C`).
- Reject reserved names (`PATH`, `HOME`, `DYLD_*`, `LD_*`, `NODE_OPTIONS`, `PYTHONPATH`, `PM_*`, …)
  unless `--allow-reserved` is passed. Checked before the Touch ID prompt.

Prefix match for inject/list: exact path **or** paths starting with `{prefix}/`
(exact, case-sensitive comparison; not `LIKE`, whose `_`/`%` are wildcards).

---

## Storage layout (`$PM_DATA`)

```
$PM_DATA/           # mode 0700 (enforced on every command)
  .git/            # auto-init; commits on set/rm/init
  keys.db          # SQLite secrets
  .lock            # exclusive write lock (fs4); gitignored
  .session         # unlocked master-key cache; mode 0600; gitignored
  .gitignore       # .lock, .session, SQLite side files (-journal, -wal, -shm)
```

### SQLite (`keys.db`)

```sql
CREATE TABLE secrets (
  path TEXT PRIMARY KEY NOT NULL,
  nonce BLOB NOT NULL,       -- 24 bytes (XChaCha20)
  ciphertext BLOB NOT NULL,
  updated_at INTEGER NOT NULL
);
```

Only ciphertext on disk. Rollback journal (`journal_mode=DELETE`), not WAL, so each write is in `keys.db` before the git commit.

### Session file (`.session`)

Owner-only file. Preferred format, with a local ssh-agent (`agent.rs`):

```
v3
<expires_unix_secs>
<unlocked_at_unix_secs>
<agent_socket_path>
<ed25519_public_key_hex>
<challenge_hex>        # 32 random bytes
<nonce_hex>
<ciphertext_hex>       # master key, XChaCha20-Poly1305
```

- On unlock: generate a throwaway ed25519 key, add it to the agent with lifetime
  `PM_SESSION_MAX` (`SSH2_AGENTC_ADD_ID_CONSTRAINED`), have the agent sign
  `"pm-session-v3\0" || challenge`, derive the session key as
  `HKDF-SHA256(salt = challenge, ikm = signature, info = "pm session key v3")`, and
  encrypt the master key (AAD = context, unlocked_at, public key, challenge).
- On use: ask the agent to sign again (ed25519 is deterministic → same key) and verify
  the signature against the stored public key before deriving.
- `pm lock` / expiry / corruption remove the key from the agent too.
- Agent not used when `SSH_CONNECTION` is set (forwarded agent).

Fallback without a usable agent (warning printed):

```
v2
<expires_unix_secs>
<unlocked_at_unix_secs>
<master_key_hex>
```

- Sliding TTL: each successful use via session extends expiry by TTL from *now*,
  capped at `unlocked_at + PM_SESSION_MAX`, so constant use can't keep it unlocked forever.
- Older `v1` files are discarded (one extra Touch ID prompt).
- Corrupt / expired → delete and require Touch ID again.

### Git

- Shell out to `git` (`gitutil.rs`).
- Commit identity forced per commit: `user.name=pm`, `user.email=pm@local` (no global git config required).
- Commit messages are path operations only (`set /env/dev/url`) — **never** secret values.
- Nothing to commit → no-op (clean staged tree).

---

## Security model

### Master key

- 32 random bytes at `init`.
- Stored in **macOS Keychain** via `security-framework`:
  - service: `pm.master-key`
  - account: `pm:{absolute PM_DATA path}` (per-vault)
- Stored as hex password bytes.

### Per-secret crypto (`crypto.rs`)

- **XChaCha20-Poly1305**
- Random 24-byte nonce per value
- **AAD = path bytes** (ciphertext cannot be moved under another path)
- Buffers wrapped with `zeroize` where practical

### Touch ID (`auth.rs`)

- `LocalAuthentication` via `objc2-local-authentication`
- Prefer `DeviceOwnerAuthenticationWithBiometrics`, else `DeviceOwnerAuthentication`
- Async reply + **NSRunLoop pump** (required for CLI Touch ID UI)
- Gate then read Keychain (Keychain item itself is not biometry-ACL’d in v1; the LA prompt is the gate)

### Session cache tradeoff

- Cross-process convenience: any process of the same user can use an unlocked session
  (read the v2 file, or ask the agent to unseal v3). Only a custom agent that verifies
  the calling binary could prevent that.
- v3 keeps the key off disk: a leaked/copied `.session` is useless, and the agent enforces
  the hard limit.
- Mitigations: `0600` file in a `0700` dir, gitignored, short TTL, hard max lifetime,
  `pm lock`, TTL=`0`.

### Other notes

- `list` does not decrypt (paths only).
- Clipboard (`arboard`): copies are marked concealed (skipped by clipboard managers) and
  cleared after `PM_CLIPBOARD_CLEAR` seconds (default 45) by a detached helper, only if
  the clipboard still holds the secret.
- Git history keeps every old value (ciphertext) and path names in commit messages; `rm`
  only removes from the current `keys.db` (zeroed via `secure_delete`). README documents
  how to wipe history.
- `inject` puts secrets in the child environment (by design).

---

## Source map

```
src/
  main.rs       # clap CLI + command handlers
  config.rs     # PM_DATA / DataDir paths
  store.rs      # SQLite + write lock
  crypto.rs     # MasterKey, encrypt/decrypt
  auth.rs       # Keychain + Touch ID
  session.rs    # .session cache load/save/clear/status (v3 sealed via agent, v2 fallback)
  agent.rs      # minimal ssh-agent client (add with lifetime, sign, remove)
  pathutil.rs   # normalize_path, path_to_env_name
  gitutil.rs    # git init / add / commit
```

Dependencies (high level): `clap`, `rusqlite` (bundled), `fs4`, `chacha20poly1305`, `zeroize`, `rpassword`, `arboard`, `anyhow`, `ed25519-dalek` + `hkdf` + `sha2` (session sealing), macOS: `security-framework`, `objc2*`, `block2`.

---

## Architecture decisions (locked in)

| Topic | Choice |
|-------|--------|
| DB | Single SQLite file (`keys.db`) |
| Cipher | XChaCha20-Poly1305, AAD = path |
| Auth UX | Touch ID (LA) before Keychain master-key use |
| Session | Sliding TTL (default 180s) + hard max (default 900s); key sealed via ssh-agent, plaintext fallback |
| Git | Shell `git`, commit on write |
| Default data dir | **None** — `PM_DATA` required (no silent `~/.…` default) |
| Platform | macOS-first (Touch ID); non-macOS Touch ID errors out |

---

## What was proposed earlier (plan) vs status

From the initial build plan discussion:

| Item | Status |
|------|--------|
| Phase 0 — clap skeleton | Done |
| Phase 1 — SQLite + lock + path→env | Done |
| Phase 2 — crypto + Touch ID + Keychain | Done |
| Phase 3 — git on write | Done |
| Phase 4 — stdin/prompt, clipboard, inject | Done |
| Phase 5 — session cache | Done (sealed via ssh-agent, plaintext file fallback) |
| `list` / `rm` | Done |
| Default `~/.local/share/pm` if `PM_DATA` unset | **Not done** (still required) |
| Keychain item with biometry ACL on the secret itself | **Not done** (LA gate + generic password) |
| In-memory unlock agent (ssh-agent style) | Partial: key sealed via ssh-agent; no caller verification |
| Clipboard auto-clear timer | Done (`PM_CLIPBOARD_CLEAR`, default 45s) |
| `pm rename` | **Not done** |
| Biometry mock / `PM_SKIP_TOUCH_ID` for CI | **Not done** |
| Integration test harness with temp vault | Partial (unit tests for pathutil + session only) |
| Non-macOS backend | **Not done** |

---

## Sensible next steps (if continuing)

1. **Hardening**
   - Optional Secure Enclave / Keychain ACL requiring biometry to *read* the master key (in addition to LA gate).
   - Custom agent that verifies the calling binary (peer PID → code signature) before
     unsealing; the ssh-agent seal can't tell pm from other same-user processes.

2. **UX**
   - `pm rename <from> <to>` (re-encrypt under new path AAD).
   - Default `PM_DATA` to `~/.local/share/pm` when unset (document clearly).
   - `pm export` / `pm import` encrypted backup (careful design).

3. **Quality**
   - Integration tests with a test feature that stubs Touch ID.
   - Ensure existing vaults get `.session` in `.gitignore` (already patched on session save).
   - Consider refusing to run if `.session` permissions are not `0600`.

4. **Ops**
   - Install target (`cargo install --path .`) and maybe a Homebrew formula later.
   - Document Keychain item cleanup if wiping a vault (`security delete-generic-password …`).

---

## Testing today

```bash
cargo test          # pathutil + session roundtrip
cargo build --release
```

End-to-end secret flows need a real Mac + Touch ID (or device password) and a throwaway `PM_DATA`.

---

## Agent notes

- Do **not** commit secrets, `.session`, or real `PM_DATA` contents.
- Prefer extending existing modules over new abstractions.
- Keep commit messages free of secret values.
- Touch ID from CLI requires run-loop pumping (`auth.rs`); don’t “simplify” that away.
- Session is a deliberate security/UX tradeoff; changing it to an agent is a feature, not a drive-by refactor.
