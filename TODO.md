# COG onboarding and distribution TODO

The intended default native layout is:

```text
~/.cog/
├── master.key
└── data/
    └── cog.sqlite
```

On Windows, the equivalent cog home should live under `%LOCALAPPDATA%\cog`.

## P0 — Default local layout

- [ ] Introduce a platform-aware cog home directory:
  - Linux and macOS: `~/.cog`
  - Windows: `%LOCALAPPDATA%\cog`
  - Optional override: `COG_HOME`
- [ ] Default `COG_DATA_DIR` to `<cog-home>/data`.
- [ ] Store the generated master key at `<cog-home>/master.key`.
- [ ] Preserve explicit configuration precedence:
  1. CLI option
  2. Existing environment variable
  3. Cog-home default
- [ ] Keep Docker explicitly configured with `COG_DATA_DIR=/data`; native defaults should not alter the container layout.
- [ ] Create the cog home and data directories automatically.
- [ ] Apply restrictive permissions to the cog home, master key, and database where supported.
- [ ] Reserve `data/` for database working state rather than unrelated configuration or temporary files.

## P0 — Persistent master-key initialization

- [ ] Make `COG_MASTER_KEY` optional during argument parsing.
- [ ] Resolve the master key in this order:
  1. Explicit `COG_MASTER_KEY`
  2. Existing `<cog-home>/master.key`
  3. Newly generated cryptographically random key
- [ ] Atomically create `master.key` on first use so simultaneous processes cannot generate different keys.
- [ ] Set Unix permissions to `0600` and restrict access to the current user on Windows.
- [ ] Never silently replace an unreadable, malformed, or empty key file.
- [ ] Never generate a new key when a database already exists but its key is missing; fail with a recovery-oriented error instead.
- [ ] Add tests for initial generation, restart reuse, explicit override, invalid key files, a missing key with existing data, and concurrent initialization.

## P0 — Explicit first-user bootstrap

- [ ] After opening or restoring the database, check `user_count()`.
- [ ] If there are no users, exit before binding the HTTP listener.
- [ ] Print a direct remediation command, for example:

  ```text
  No users exist. Create the first user with:
    cog create-user owner@example.com --password-stdin
  ```

- [ ] Make `create-user` fully non-interactive.
- [ ] Prefer a concise command shape:

  ```sh
  cog create-user USERNAME --password-stdin
  ```

- [ ] Decide whether `USERNAME` replaces the existing email identity or is the email positional argument. Using the existing email field avoids an unnecessary schema migration.
- [ ] Remove interactive password prompting.
- [ ] Retain `--password-stdin` as the safe automation path.
- [ ] If direct password arguments are a firm requirement, optionally add `--password VALUE` and warn in `--help` and the README that it can leak through shell history and process inspection.
- [ ] Ensure `create-user` uses the same cog home, data directory, master key, and optional S3 configuration as normal startup.
- [ ] Add integration coverage for this sequence:
  1. Bare `cog` creates local state but exits because no user exists.
  2. Non-interactive `create-user` succeeds.
  3. Bare `cog` then starts and serves `/readyz`.
  4. Restart preserves the user and encryption key.

## P0 — Local-only storage by default

- [ ] Keep S3 disabled unless `COG_S3_BUCKET` is explicitly configured.
- [ ] Add a regression test proving bare startup never initializes an S3 client, lease, restore, or replicator.
- [ ] Keep the existing local/S3 storage-mode marker so an existing database cannot accidentally switch modes.
- [ ] Consider defaulting native installations to `127.0.0.1:4788`; Docker and production deployments can explicitly use `0.0.0.0:4788`.

## P0 — Proper database migrations and version metadata

- [ ] Retain `schema_meta`, but convert it into a real ordered migration mechanism.
- [ ] Replace the large `CREATE TABLE IF NOT EXISTS` block and scattered column-existence checks with numbered transactional migrations, for example:
  1. Initial schema
  2. Identity schema
  3. Refresh-token expiry
  4. Git credentials
- [ ] Run every pending migration in order inside transactions.
- [ ] Update the schema version only after its migration succeeds.
- [ ] Refuse to open a database whose schema version is newer than the binary supports.
- [ ] Make migration failures leave the previous schema version intact and return a clear backup/recovery message.
- [ ] Store a separate informational `last_opened_by_version` value in `cog_meta` after migrations and startup validation succeed.
- [ ] Do not use application semantic versions to select migrations; releases and schemas do not necessarily advance together.
- [ ] Expose binary and schema versions through `/version` or diagnostics.
- [ ] Add tests for each supported upgrade path, interrupted migrations, repeated startup, newer-schema rejection, and local/S3-restored databases.

## P0 — Repair releases and installation

- [ ] Replace all stale `rexec` names in the release workflow with `cog`.
- [ ] Change `REXEC_FRONTEND_PREBUILT` to `COG_FRONTEND_PREBUILT`.
- [ ] Publish these archives:
  - `cog-x86_64-unknown-linux-gnu.tar.gz`
  - `cog-aarch64-unknown-linux-gnu.tar.gz`
  - `cog-x86_64-apple-darwin.tar.gz`
  - `cog-aarch64-apple-darwin.tar.gz`
  - `cog-x86_64-pc-windows-msvc.zip`
- [ ] Ensure each archive contains `cog` or `cog.exe`.
- [ ] Generate `SHA256SUMS` over `cog-*`.
- [ ] Replace `OWNER/cog` with the canonical public release repository.
- [ ] Provide a stable Unix installation command:

  ```sh
  curl -fsSL https://get.example.com/cog | sh
  ```

- [ ] Provide a corresponding Windows PowerShell command:

  ```powershell
  irm https://get.example.com/cog.ps1 | iex
  ```

- [ ] Keep platform detection, checksum verification, version pinning, and installation-directory overrides.
- [ ] Add installer tests for OS/architecture mapping, checksum rejection, archive naming and contents, unsupported platforms, and install paths containing spaces.
- [ ] Add a post-release job that downloads every published asset through the installer path and executes `cog --version`.

## P1 — Simplify the README

- [ ] Open with one sentence describing cog.
- [ ] Put the Unix installation command first, with Windows immediately below it.
- [ ] Show the minimal first-run sequence:

  ```sh
  cog
  printf '%s\n' "$PASSWORD" | cog create-user owner@example.com --password-stdin
  cog
  ```

- [ ] Explain that the first `cog` initializes `~/.cog` and intentionally exits until an owner exists.
- [ ] Tell the user to open `http://localhost:4788`.
- [ ] Briefly describe the default files:

  ```text
  ~/.cog/master.key
  ~/.cog/data/cog.sqlite
  ```

- [ ] Keep the first screenful limited to installation, initialization, user creation, startup, and opening the application.
- [ ] Move Docker, S3, TLS, OAuth internals, Git integrations, full configuration, recovery, and development farther down.
- [ ] Link to `docs/operations.md` for S3, backup, restore, and key-handling details.
- [ ] Exercise the README's installation and first-run commands in CI.
