# pm: bugs and security review

Review of `src/` (8 files) on 2026-10-08. Finding #1 was reproduced with a test. The others come from reading the code.

**Status:** everything is fixed on branch `fix/critical-bugs` except #6 (needs a code-signed binary) and the rest of #4 (mitigated: see its section), and two minor items marked won't fix.

| # | Severity | Title | Location | Status |
|---|----------|-------|----------|--------|
| 1 | 🔴 Critical | Git commits are always one change behind (WAL) | `store.rs:33`, `main.rs:210,388` | ✅ `cf41182` |
| 2 | 🔴 Critical | `LIKE` prefix matching can select the wrong secrets | `store.rs:121,151` | ✅ `c0e02e4` |
| 3 | 🔴 Critical | A failed `pm init` leaves the vault stuck | `main.rs:140-145` | ✅ `0077b2e` |
| 4 | 🟠 Security | The master key sits in a plain file during a session | `session.rs:79-111` | 🟡 Mitigated `89961ce` |
| 5 | 🟠 Security | A session can be kept unlocked forever | `main.rs:157-159` | ✅ `fa8b8aa` |
| 6 | 🟠 Security | Touch ID is only a prompt, not part of the encryption | `auth.rs:16-23` | ⏸ Needs code signing |
| 7 | 🟠 Security | Deleted and rotated secrets stay in git history forever | `gitutil.rs` | ✅ `5a7e64f`, `9a1cbed` |
| 8 | 🟠 Security | Paths are visible without authentication | `main.rs:345`, `config.rs:42` | ✅ `8ee69f0` |
| 9 | 🟠 Security | Clipboard copies are never cleared | `main.rs:237-243` | ✅ `2f2c1cc` |
| 10 | 🟡 Bug | Values with surrounding quotes get changed | `main.rs:227,293,426` | ✅ `923572a` |
| 11 | 🟡 Bug | `dump` output isn't valid dotenv | `main.rs:339` | ✅ `f6eba3b` |
| 12 | 🟡 Bug | Different paths can produce the same env name | `pathutil.rs:48-94` | ✅ `a8966cf` |
| 13 | 🟡 Bug | Saving to the DB and committing to git are separate steps | `main.rs:205-210` | ✅ `53b5779` |
| 14 | 🟡 Bug | The Keychain account depends on how `PM_DATA` is spelled | `auth.rs:13` | ✅ `5524481` |
| 15 | ⚪ Minor | Various small issues | see below | ✅ mostly (see below) |

---

## 🔴 Critical bugs

### 1. Git commits are always one change behind (WAL mode). Confirmed. ✅ Fixed in `cf41182`

**Where:** `store.rs:33` (`PRAGMA journal_mode=WAL`) and `main.rs:210` and `388` (`commit_db` called while `store` is still open).

**Problem:** In WAL mode, new writes go to `keys.db-wal`, not `keys.db`. The WAL is only merged into `keys.db` when the connection closes. In `cmd_set` and `cmd_rm`, `store` is dropped at the end of the function, after `commit_db` has already run.

**Test output** (scratch repo, same pragma and the same git steps as `commit_db`):

```
db hash while conn open: 938b165733
staged diff exists (pm would commit)? False   ← no commit made
db hash after close:     f9cf7edaa2           ← change lands after
?? keys.db-shm
?? keys.db-wal                                ← untracked, not in .gitignore
```

**Effect:**
- The commit for `set X` is skipped, because git sees no change.
- That change then gets committed during the *next* operation, under the wrong message.
- The last change is never committed at all.
- `keys.db-wal` and `keys.db-shm` show up as untracked files.

**Fix:**
- Call `drop(store)` before `commit_db`, or switch to `PRAGMA journal_mode=DELETE`.
- Add `keys.db-wal` and `keys.db-shm` to `.gitignore`.

### 2. `LIKE` prefix matching can select the wrong secrets ✅ Fixed in `c0e02e4`

**Where:** `store.rs:121` (`list_prefix`) and `store.rs:151` (`list_paths`).

**Problem:**
- In `LIKE`, `_` matches any single character. `--prefix /env/my_app` also matches `/env/myXapp/...`, and `_` is very common in key names.
- `%` in a path is never escaped. `list_prefix` declares `ESCAPE '\\'` but never escapes anything, and `list_paths` has no `ESCAPE` at all.
- `LIKE` ignores ASCII case in SQLite, so `/env/Prod` matches `/env/prod/...`.

**Effect:** `inject` and `dump` can load secrets from a different prefix into a process.

**Fix:** Use an exact comparison instead of `LIKE`:

```sql
WHERE path = ?1 OR substr(path, 1, length(?1) + 1) = ?1 || '/'
```

### 3. A failed `pm init` leaves the vault stuck ✅ Fixed in `0077b2e`

**Where:** `main.rs:140-145`.

**Problem:** `Store::open` creates `keys.db` *before* the Touch ID prompt and before the master key is stored. If you cancel Touch ID or it fails, `keys.db` exists but no master key does.

**Effect:**
- Every later `pm init` says "already initialized".
- Every other command fails with "load master key".
- The only way out is deleting `keys.db` by hand.

**Fix:** Run Touch ID and store the key first, then create the DB. Or remove `keys.db` if a later step fails.

**Related:** `store_master_key` deletes any existing Keychain item first (`auth.rs:19`). If someone deleted `keys.db` to restore it from git and then re-runs `init`, the old master key is overwritten and the whole history can no longer be decrypted. `init` should refuse when a key already exists.

---

## 🟠 Security issues

### 4. The master key sits in a plain file during a session 🟡 Mitigated in `89961ce`

**Where:** `session.rs:79-111`.

**Problem:** `.session` holds the master key in hex. File mode `0600` doesn't protect against your own processes.

**Effect:** Any process running as you (an npm postinstall script, an editor extension, a compromised dev tool) can `cat` the file and get the master key. That bypasses Touch ID and the Keychain entirely.

**Mitigated in `89961ce`:** with a local ssh-agent, `.session` holds only the master key encrypted under a key derived from a signature by a throwaway ed25519 key. That key lives only in the agent, with the hard session limit as its agent lifetime. A copy of the file is useless, and `pm lock`, `ssh-add -D` or logout end the session. Without a usable agent, pm warns and falls back to the plaintext file.

**Still open:** same-user processes can still use an unlocked session, because they can ask the agent too. Fully fixing that needs a custom agent that verifies the calling binary.

**Fix options:**
- Keep the session in memory in a small agent process (like `ssh-agent`) that talks over a `0600` Unix socket and checks the caller's identity.
- Or encrypt the session file with a key kept in the Keychain without user prompts. This is weaker but better than plaintext.

### 5. A session can be kept unlocked forever ✅ Fixed in `fa8b8aa`

**Where:** `main.rs:157-159` (`session::touch` on every use).

**Problem:** Every `get`, `set`, `dump`, `inject` and `rm` extends the TTL, with no maximum lifetime.

**Effect:**
- A background script calling `pm dump` every 2 minutes keeps the vault unlocked indefinitely, with no prompt.
- A process started by `pm inject` can call `pm dump` itself and keep extending the session.

**Fix:** Store `unlocked_at` in the session as well. Allow sliding expiry, but never past `unlocked_at + MAX` (e.g. 15 min).

### 6. Touch ID is only a prompt, not part of the encryption ⏸ Open: needs a code-signed binary

**Where:** `auth.rs:16-23`.

**Problem:** The Keychain item is created with default access rules. Touch ID is a check that `pm` chooses to run before reading the item. Nothing in the Keychain requires it.

**Effect:** Anything that can read the item (for example a patched `pm` build that the user approves at the Keychain prompt), or that can read the session file, skips Touch ID.

**Fix:** Create the item with `SecAccessControl` using `.biometryCurrentSet` (or `.userPresence`). The OS then enforces Touch ID when the item is read.

**Why still open:** tested on 2026-10-08 with a throwaway item. A locally built (ad-hoc signed) binary gets `-34018 errSecMissingEntitlement` for biometric access control, in both the file-based and the data-protection keychain. It needs a binary signed with an Apple Developer ID and a provisioning profile with a keychain-access-groups entitlement.

### 7. Deleted and rotated secrets stay in git history forever ✅ Fixed in `5a7e64f` (keys.db) and documented in `9a1cbed` (git history)

**Where:** `gitutil.rs`, design.

**Problem:**
- `rm` and overwrites don't erase old ciphertext. Every past value stays in `.git`.
- Commit messages contain paths in plaintext (`set /env/prod/stripe_key`).

**Effect:** After rotating a leaked secret, the leaked value is still stored. If the master key is ever compromised, every value that ever existed can be decrypted. Anyone who can read the repo, or a remote you push to, sees all key names.

**Fix options:**
- Document this behavior clearly.
- Use generic commit messages.
- Add a `pm purge` command, or document how to rewrite history.
- Add an opt-out (`PM_GIT=0`).

### 8. Paths are visible without authentication ✅ Fixed in `8ee69f0`

**Where:** `main.rs:345` (`cmd_list`) and `config.rs:42` (`ensure_dir`).

**Problem:**
- `pm list` needs no Touch ID.
- The data dir, `keys.db` and `.git` are created with the default umask (usually `0755`/`0644`).

**Effect:** Other local users can read every path name, plus the ciphertext.

**Fix:** Create `PM_DATA` with mode `0700`. Optionally require a session for `list`.

### 9. Clipboard copies are never cleared ✅ Fixed in `2f2c1cc`

**Where:** `main.rs:237-243`.

**Problem:** `get -o clipboard` leaves the secret on the pasteboard indefinitely.

**Effect:** Clipboard-history apps (Raycast, Alfred, Paste…) save it permanently.

**Fix:**
- Mark the copy with the `org.nspasteboard.ConcealedType` pasteboard type so clipboard managers skip it.
- Start a background process that clears the clipboard after N seconds, but only if it still holds the secret.

---

## 🟡 Correctness bugs

### 10. Values with surrounding quotes get changed ✅ Fixed in `923572a`

**Where:** `strip_surrounding_quotes` runs on `set` (`main.rs:426`) and again on `get` and `dump` (`main.rs:227,293`).

**Effect:**
- The stored value `"'abc'"` is returned as `abc`.
- Any password that starts and ends with `"` or `'` loses those characters.
- You can never get back the exact bytes you stored.

**Fix:** Strip once on input at most, ideally only behind a flag. Never strip on output.

### 11. `dump` output isn't valid dotenv ✅ Fixed in `f6eba3b`

**Where:** `main.rs:339`.

**Problem:** Values are written as `NAME=value` with no quoting or escaping.

**Effect:**
- Values containing spaces, `#`, `$` or quotes are misread by dotenv parsers.
- A value containing `\nOTHER=x` adds an extra variable line to the output.

**Fix:** Write values in single quotes and escape `'` inside them (or use double quotes with escaping). Reject or escape newlines.

### 12. Different paths can produce the same env name ✅ Fixed in `a8966cf`

**Where:** `pathutil.rs:48-94`, used by `load_env_pairs` (`main.rs:288-295`).

**Problem:**
- `/a/b-c`, `/a/b_c`, `/a/b.c`, `/a/B_C` and `/a/b/c` all map to `A_B_C`.
- `--mask` can produce sensitive names such as `PATH`, `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS` or `BASH_ENV`.

**Effect:** `inject` silently keeps the last value, and `dump` prints duplicates. A stored secret can override how the child process loads code.

**Fix:** Fail when two paths map to the same name. Refuse a list of dangerous names unless a flag such as `--allow-reserved` is passed.

### 13. Saving to the DB and committing to git are separate steps ✅ Fixed in `53b5779`

**Where:** `main.rs:205-210`.

**Problem:**
- The secret is saved before the commit. If the commit fails (git not installed, `.git/index.lock` held, a global `commit.gpgsign` or `core.hooksPath` setting), the command exits with an error even though the secret was saved.
- The write lock is released *before* `commit_db` (`main.rs:208`), so two concurrent `pm set` commands race on git.

**Fix:**
- Keep the lock until the commit finishes.
- Run git with `-c commit.gpgsign=false -c core.hooksPath=/dev/null`.
- Turn a commit failure into a warning, since the data was already saved.

### 14. The Keychain account depends on how `PM_DATA` is spelled ✅ Fixed in `5524481`

**Where:** `auth.rs:13`.

**Problem:** The account name is `pm:{PM_DATA as typed}`.

**Effect:** A trailing slash, a relative path (`PM_DATA=./vault`) or a symlinked path is treated as a different vault, and every command fails with "load master key".

**Fix:** Canonicalize the path in `DataDir::resolve()` (`fs::canonicalize`, after creating the dir during init).

---

## ⚪ 15. Minor issues

- ✅ `032056f`. **Memory clean-up has gaps.** `Zeroizing` doesn't cover the intermediate copies: `raw`/`buf` in `read_secret_value`, the `String::from_utf8(plaintext.to_vec())` copies, and the `rpassword` result. These plaintext copies are never wiped. `process::exit` in `cmd_inject` (`main.rs:330`) also skips the wipes.
- ✅ `f1f6e2d`. **Possible abort in the Touch ID callback.** `.expect()` inside the Objective-C callback (`auth.rs:76`) would abort the process across the FFI boundary. Return an error string instead.
- ✅ `aaf57a2`. **Paths aren't checked for control characters.** `normalize_path` allows newlines and control characters, which can produce multi-line commit messages and misleading `list` output.
- ✅ `fa8b8aa` (the new session parser returns "locked"). **`status` can crash on a bad session file.** `remaining_secs` returns an error on a malformed `.session` and makes `pm status` fail. `load` deletes the file quietly instead.
- ✅ `0077b2e`. **Dead code.** `load_or_create_master_key(..., create_if_missing)` is always called with `false`.
- ✅ `fe6ceed`. **TTL 0 doesn't force Touch ID once.** With `--session-ttl 0`, an existing session is still used once (`main.rs:157`) before being cleared.
- Won't fix: `pm list` shows all paths anyway, and checking first avoids a Touch ID prompt for a typo. **`get` leaks existence before auth.** `get` returns "key not found" before Touch ID. This doesn't matter much given #8, but it reveals which keys exist.
- Won't fix: changing the clock needs admin rights, or the same user who can already read `.session`. **The session check trusts the system clock.** Setting the clock back extends the session.
