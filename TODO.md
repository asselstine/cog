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

- [x] Introduce a platform-aware cog home directory:
  - Linux and macOS: `~/.cog`
  - Windows: `%LOCALAPPDATA%\cog`
  - Optional override: `COG_HOME`
- [x] Default `COG_DATA_DIR` to `<cog-home>/data`.
- [x] Store the generated master key at `<cog-home>/master.key`.
- [x] Preserve explicit configuration precedence:
  1. CLI option
  2. Existing environment variable
  3. Cog-home default
- [x] Keep Docker explicitly configured with `COG_DATA_DIR=/data`; native defaults should not alter the container layout.
- [x] Create the cog home and data directories automatically.
- [x] Apply restrictive permissions to the cog home, master key, and database where supported.
- [x] Reserve `data/` for database working state rather than unrelated configuration or temporary files.

## P0 — Persistent master-key initialization

- [x] Make `COG_MASTER_KEY` optional during argument parsing.
- [x] Resolve the master key in this order:
  1. Explicit `COG_MASTER_KEY`
  2. Existing `<cog-home>/master.key`
  3. Newly generated cryptographically random key
- [x] Atomically create `master.key` on first use so simultaneous processes cannot generate different keys.
- [x] Set Unix permissions to `0600` and restrict access to the current user on Windows.
- [x] Never silently replace an unreadable, malformed, or empty key file.
- [x] Never generate a new key when a database already exists but its key is missing; fail with a recovery-oriented error instead.
- [x] Add tests for initial generation, restart reuse, explicit override, invalid key files, a missing key with existing data, and concurrent initialization.

## P0 — Explicit first-user bootstrap

- [x] After opening or restoring the database, check `user_count()`.
- [x] If there are no users, exit before binding the HTTP listener.
- [x] Print a direct remediation command, for example:

  ```text
  No users exist. Create the first user with:
    cog create-user $EMAIL $PASSWORD
  ```

- [x] Make `create-user` fully non-interactive.
- [x] Prefer a concise command shape:

  ```sh
  cog create-user EMAIL PASSWORD
  ```

- [x] Decide whether `USERNAME` replaces the existing email identity or is the email positional argument. Using the existing email field avoids an unnecessary schema migration.
- [x] Remove interactive password prompting.
- [x] Retain `--password-stdin` as the safe automation path.
- [x] If direct password arguments are a firm requirement, optionally add `--password VALUE` and warn in `--help` and the README that it can leak through shell history and process inspection.
- [x] Ensure `create-user` uses the same cog home, data directory, master key, and optional S3 configuration as normal startup.
- [x] Add integration coverage for this sequence:
  1. Non-interactive `create-user` initializes local state and succeeds.
  2. Bare `cog` then starts and serves `/readyz`.
  3. Restart preserves the user and encryption key.

## P0 — Local-only storage by default

- [x] Keep S3 disabled unless `COG_S3_BUCKET` is explicitly configured.
- [x] Add a regression test proving bare startup never initializes an S3 client, lease, restore, or replicator.
- [x] Keep the existing local/S3 storage-mode marker so an existing database cannot accidentally switch modes.
- [x] Consider defaulting native installations to `127.0.0.1:4788`; Docker and production deployments can explicitly use `0.0.0.0:4788`.

## P0 — Proper database migrations and version metadata

- [x] Retain `schema_meta`, but convert it into a real ordered migration mechanism.
- [x] Replace the large `CREATE TABLE IF NOT EXISTS` block and scattered column-existence checks with numbered transactional migrations, for example:
  1. Initial schema
  2. Identity schema
  3. Refresh-token expiry
  4. Git credentials
- [x] Run every pending migration in order inside transactions.
- [x] Update the schema version only after its migration succeeds.
- [x] Refuse to open a database whose schema version is newer than the binary supports.
- [x] Make migration failures leave the previous schema version intact and return a clear backup/recovery message.
- [x] Store a separate informational `last_opened_by_version` value in `cog_meta` after migrations and startup validation succeed.
- [x] Do not use application semantic versions to select migrations; releases and schemas do not necessarily advance together.
- [x] Expose binary and schema versions through `/version` or diagnostics.
- [x] Add tests for each supported upgrade path, interrupted migrations, repeated startup, newer-schema rejection, and local/S3-restored databases.

## P0 — Repair releases and installation

- [x] Replace all stale `rexec` names in the release workflow with `cog`.
- [x] Change `REXEC_FRONTEND_PREBUILT` to `COG_FRONTEND_PREBUILT`.
- [x] Publish these archives:
  - `cog-x86_64-unknown-linux-gnu.tar.gz`
  - `cog-aarch64-unknown-linux-gnu.tar.gz`
  - `cog-x86_64-apple-darwin.tar.gz`
  - `cog-aarch64-apple-darwin.tar.gz`
  - `cog-x86_64-pc-windows-msvc.zip`
- [x] Ensure each archive contains `cog` or `cog.exe`.
- [x] Generate `SHA256SUMS` over `cog-*`.
- [x] Replace `OWNER/cog` with the canonical public release repository.
- [x] Provide a stable Unix installation command:

  ```sh
  curl -fsSL https://get.example.com/cog | sh
  ```

- [x] Provide a corresponding Windows PowerShell command:

  ```powershell
  irm https://get.example.com/cog.ps1 | iex
  ```

- [x] Keep platform detection, checksum verification, version pinning, and installation-directory overrides.
- [x] Add installer tests for OS/architecture mapping, checksum rejection, archive naming and contents, unsupported platforms, and install paths containing spaces.
- [x] Add a post-release job that downloads every published asset through the installer path and executes `cog --version`.

## P1 — Simplify the README

- [x] Open with one sentence describing cog.
- [x] Put the Unix installation command first, with Windows immediately below it.
- [x] Show the minimal first-run sequence:

  ```sh
  cog create-user $EMAIL $PASSWORD
  cog
  ```

- [x] Explain that `create-user` initializes `~/.cog` automatically.
- [x] Tell the user to open `http://localhost:4788`.
- [x] Briefly describe the default files:

  ```text
  ~/.cog/master.key
  ~/.cog/data/cog.sqlite
  ```

- [x] Keep the first screenful limited to installation, initialization, user creation, startup, and opening the application.
- [x] Move Docker, S3, TLS, OAuth internals, Git integrations, full configuration, recovery, and development farther down.
- [x] Link to `docs/operations.md` for S3, backup, restore, and key-handling details.
- [x] Exercise the README's installation and first-run commands in CI.
