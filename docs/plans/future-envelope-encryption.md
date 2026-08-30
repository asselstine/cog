# Future Envelope Encryption Plan

## Status

This document records a possible future design. It is not implemented and does
not describe the current credential-storage format.

## Objective

Replace COG's single server-wide credential-encryption domain with independent,
tenant-controlled encryption domains. A stolen SQLite database, S3 replica, or
backup should not be sufficient to decrypt tenant credentials, and compromise
of one tenant's key should not expose another tenant's credentials.

Tenant-controlled encryption is an encryption-at-rest feature. COG must still
handle a credential in process memory while making an authorized upstream call.
It does not protect an active credential from a malicious COG process or host,
and it cannot guarantee availability against the host operator.

## Current state

COG currently derives one AES-256-GCM key from `COG_MASTER_KEY` and uses it for
all encrypted credential material. This protects database and backup contents
when the master key is unavailable, but all tenants share one cryptographic
failure domain.

Encrypted material includes, or may include:

- Upstream OAuth access and refresh tokens.
- Static integration authentication headers.
- GitHub App private keys.
- PKCE verifiers and temporary authorization state.

## Proposed cryptographic model

Use envelope encryption with a distinct key-encryption key (KEK) controlled by
each tenant and a random data-encryption key (DEK) for each credential record.

```text
credential plaintext
        |
        | encrypted with a random credential DEK
        v
credential ciphertext

credential DEK
        |
        | wrapped with the tenant KEK
        v
wrapped DEK
```

COG stores only the credential ciphertext, wrapped DEK, nonces, algorithm and
format versions, tenant key reference, and authenticated metadata. It must not
store the tenant KEK.

Use an authenticated-encryption construction such as AES-256-GCM. Bind at least
the following values as associated authenticated data:

- Tenant ID.
- Integration ID.
- Credential type.
- Credential-record ID.
- Schema and encryption-format version.
- Tenant key version.

This binding must prevent a database operator from moving a valid ciphertext or
wrapped DEK into another tenant, integration, or credential slot.

An illustrative record format is:

```json
{
  "formatVersion": 1,
  "algorithm": "AES-256-GCM",
  "tenantKeyProvider": "aws-kms",
  "tenantKeyReference": "arn:aws:kms:us-east-1:123456789012:key/example",
  "tenantKeyVersion": 3,
  "ciphertext": "...",
  "nonce": "...",
  "wrappedDek": "...",
  "wrapMetadata": "..."
}
```

The exact representation should use binary-safe, versioned fields rather than
relying on an unversioned JSON blob.

## Key ownership

The encryption root should normally belong to the tenant, not an individual
agent. Integrations are tenant resources and may be shared by several authorized
agents.

Agent OAuth authorization and credential encryption remain separate concerns:

```text
agent OAuth grant -> whether the agent may use an integration
tenant KEK        -> whether stored integration credentials can be decrypted
```

If per-agent cryptographic access is required later, wrap the same integration
DEK independently for each authorized agent public key and for a tenant-owned
recovery key. Do not duplicate or re-encrypt the underlying credential merely
to share it with another agent.

## Supported key-management modes

### Tenant-managed KMS

This should be the preferred unattended mode. Initial providers may include:

- AWS KMS using a cross-account IAM role and tenant-specific external ID.
- Google Cloud KMS using workload identity or a dedicated service account.
- Azure Key Vault or Managed HSM using a tenant-approved application identity.
- Vault Transit using narrowly scoped tenant credentials.

COG asks the tenant's KMS to generate or unwrap DEKs. The KMS policy, audit log,
rotation policy, and ultimate revocation control remain with the tenant.

KMS improves stored-data isolation and tenant control, but an authorized COG
process receives the unwrapped DEK and plaintext credential during active use.

### Client-supplied session unlock

As an optional mode, a tenant client may supply an unlock key for a bounded
session. COG holds the key only in memory, expires it after a configured period,
and loses it on restart. While locked, COG cannot refresh tokens, execute
scheduled work, or call affected integrations.

This mode is useful for tenants that prefer manual unlock semantics, but it is
less suitable for unattended agents and workflows.

### Tenant-owned recovery key

Recovery must be an explicit tenant choice:

- **No recovery:** loss or deletion of the tenant KMS key permanently locks the
  stored credentials.
- **Tenant recovery key:** wrap credential DEKs for both the tenant KMS key and
  an offline key held by the tenant.

COG must not silently create or retain a recovery path that defeats tenant key
ownership.

## Administrator experience

### Initial configuration

Expose a tenant security setting similar to:

```text
Credential encryption
  ( ) Managed by COG
  (x) Use our KMS key
```

After choosing a provider, request the provider-specific key reference and
authentication method. Prefer temporary or workload identities over static
cloud credentials.

For AWS, the recommended path is:

1. COG generates a tenant-specific external ID and displays the COG service
   principal.
2. COG provides a minimal IAM policy and optional Terraform or CloudFormation
   snippet.
3. The tenant creates a cross-account role and permits only the necessary KMS
   operations on the selected key.
4. The tenant enters the role ARN and KMS key ARN.
5. The tenant selects **Test connection**.

The test must perform a non-destructive generate/encrypt/decrypt round trip with
temporary data and report a sanitized result. It must not expose cloud response
bodies, credentials, plaintext key material, or ciphertext in logs.

After successful setup, show:

```text
Encryption owner: Your organization
Provider: AWS KMS
Key: alias/acme-cog
Region: us-east-1
Last verified: just now
Credentials protected: 12
```

### Connecting an integration

The ordinary integration flow should remain unchanged. When GitHub or another
provider returns a credential, COG should:

1. Obtain a new DEK from the tenant KMS.
2. Encrypt the credential immediately.
3. Store the credential ciphertext and wrapped DEK transactionally.
4. Discard plaintext and temporary key buffers as soon as practical.
5. Show that the integration is protected by the tenant's key.

Agents never receive the tenant KEK, credential DEK, upstream refresh token, or
GitHub App private key.

### Normal operation

The agent experience should not change:

```text
agent calls integration
        -> COG loads ciphertext and wrapped DEK
        -> tenant KMS unwraps the DEK
        -> COG decrypts the credential in memory
        -> COG makes the authorized upstream request
```

COG may cache unwrapped DEKs in memory for a tenant-configurable interval, such
as no cache, five minutes, or fifteen minutes. The UI must explain that KMS
revocation becomes effective after the cache expires. A no-cache policy gives
the strongest revocation semantics at the cost of latency, availability, and
KMS requests.

### Locked and unavailable states

KMS failures must fail closed. COG must not fall back to a global key or stale
unencrypted credential.

Agents should receive a structured temporary-unavailable response. The tenant
administrator should see a sanitized diagnostic distinguishing at least:

- KMS access denied.
- Cross-account role or workload-identity failure.
- Key disabled or scheduled for deletion.
- Key or region mismatch.
- Encryption-context mismatch.
- Provider timeout or outage.
- Unsupported ciphertext or key version.

Reauthorizing the upstream integration must not be presented as the remedy for
a KMS failure.

### Revocation

The tenant can revoke COG independently by disabling the KMS key or removing the
COG role or grant in the tenant's cloud account. After any in-memory cache
expires, COG can no longer decrypt stored credentials.

COG may provide a **Clear decrypted-key cache now** control, but documentation
must not claim this protects against a malicious host. The tenant-controlled
guarantee comes from the external KMS policy and the configured cache lifetime.

### Rotation

Changing from one tenant KEK to another should normally rewrap existing DEKs
without re-encrypting credential plaintext:

```text
old KEK unwraps credential DEK
        -> new KEK wraps the same credential DEK
```

Rotation must be resumable, versioned, and verified before the old wrapping is
removed. Automatic key-material rotation behind a stable KMS key reference
should require no COG migration.

The UI should report progress and retain a deliberate rollback window before
the tenant removes access to the old key.

### Offboarding

Provide a documented sequence:

1. Export encrypted credential records if the tenant wants a backup.
2. Revoke COG's external KMS grant in the tenant account.
3. Clear active key caches where cooperative immediate shutdown is desired.
4. Delete the tenant from COG.
5. Record an audit event and deletion identifier.

The tenant's strongest independent control is revoking KMS access in its own
account.

## OAuth and unattended-operation behavior

An OAuth callback delivers a new access or refresh token to COG in plaintext.
COG must have a working tenant encryption path before accepting the callback.

For tenant-managed KMS, encrypt the returned token immediately. For manual
session-unlock mode, require the tenant to be unlocked throughout OAuth setup or
fail the callback closed. Do not store a temporarily plaintext token in SQLite,
S3, logs, or a retry queue.

Automated token refresh, scheduled workflows, GitHub App token issuance, and
other unattended operations require either:

- Available tenant-managed KMS authorization; or
- An active manual unlock session.

The product must communicate this availability consequence before enabling a
manual-lock mode.

## Migration from the global master key

Migration is the highest-risk portion and must be transactional and resumable.

For each tenant:

1. Configure and verify the tenant key provider.
2. Enumerate every encrypted credential record owned by the tenant.
3. Decrypt one record using the current COG master key.
4. Generate a credential DEK and encrypt the credential using authenticated
   tenant and integration metadata.
5. Wrap the DEK with the tenant KEK.
6. Write the new version beside the old representation.
7. Read, unwrap, decrypt, and verify the new representation.
8. Mark the new representation active in the same durable transaction.
9. Retain the old representation only for a bounded rollback period.
10. Remove old ciphertext after the migration is complete and acknowledged.

Never leave a credential with neither a verified old representation nor a
verified new representation. S3 replication acknowledgements and lease
authority must cover every migration mutation before reporting success.

The administrator experience should show explicit preparation, encryption,
verification, completion, and failure states. A failure must identify the
affected integration without exposing credential material.

## Data integrity and rollback resistance

AEAD detects ciphertext modification but does not by itself prevent deletion or
rollback to an older valid record. The design should therefore include:

- Authenticated tenant, integration, record, and version metadata.
- Monotonic credential versions.
- Audit events for create, unwrap, rotate, migrate, disable, and failure.
- Detection of a stored version older than the tenant's acknowledged version.
- A future option for an external or tenant-pinned transparency record when
  rollback resistance against the storage operator is required.

Encryption cannot prevent the host from deleting data, denying service, or
returning incorrect application results.

## Operational and security requirements

- Never log tenant KEKs, plaintext DEKs, plaintext credentials, wrapped DEKs,
  cloud credentials, or provider response bodies containing secret material.
- Avoid static KMS credentials; prefer workload identity and cross-account
  roles with tenant-specific external IDs.
- Restrict KMS permissions to the selected tenant key and required operations.
- Apply timeouts, bounded retries, rate limits, and circuit breaking to KMS
  operations.
- Keep decrypted key caches tenant-isolated, bounded, observable, and clearable.
- Do not write decrypted material to crash dumps, diagnostics, generated code,
  SQLite temporary tables, or S3.
- Version every envelope format and provider-specific wrapping format.
- Preserve the existing single-owner S3 lease and durable-acknowledgement
  invariants during encryption mutations and migrations.
- Provide metrics without tenant, key, credential, ciphertext, or secret labels.
- Treat key-provider changes, migrations, and recovery operations as sensitive
  administrative actions requiring explicit scope and audit records.

## Suggested implementation phases

### Phase 1: Internal envelope format

- Introduce versioned credential envelopes and authenticated metadata.
- Continue wrapping DEKs with a COG-managed key.
- Add migration, rotation, and compatibility tests.
- Preserve read compatibility during a bounded migration period.

This phase separates credential encryption from the current global key without
yet adding external providers.

### Phase 2: Per-tenant key providers

- Add tenant encryption-policy records.
- Add a key-provider abstraction with generate, wrap, unwrap, verify, and status
  operations.
- Implement one KMS provider, preferably AWS KMS cross-account roles.
- Add tenant-isolated in-memory DEK caching and sanitized diagnostics.

### Phase 3: Administration and migration UX

- Add KMS connection, test, migration, rotation, revocation, and status UI.
- Add transactional migration jobs with durable progress.
- Add audit events and operational metrics.

### Phase 4: Additional providers and manual unlock

- Add Google Cloud KMS, Azure Key Vault or Managed HSM, and Vault Transit.
- Add client-supplied session unlock only after locked-state behavior is fully
  specified for OAuth callbacks, refresh, schedules, and restarts.

### Phase 5: Stronger rollback and enterprise controls

- Add tenant-pinned version acknowledgements or transparency integration.
- Add customer-controlled recovery wrapping.
- Add policy controls for cache lifetime and permitted key regions/providers.

## Required testing

- Envelope encryption round trips and tamper detection.
- Associated-data substitution across tenants, integrations, records, and
  versions.
- KMS denial, timeout, disabled-key, rotation, and stale-version behavior.
- Cross-tenant isolation under shared database and S3 storage.
- OAuth callback and refresh behavior when KMS is unavailable.
- Transactional migration interruption at every step.
- Process restart and S3 takeover during migration and rotation.
- Cache expiration and cooperative cache clearing.
- Recovery and no-recovery configurations.
- Redaction tests covering logs, diagnostics, metrics, APIs, and UI errors.
- Backward compatibility and final removal of the legacy ciphertext format.

## Decisions required before implementation

1. Is encryption ownership attached to a COG user, organization, or a new
   explicit tenant entity?
2. Which KMS provider is the first supported implementation?
3. Is DEK generation performed locally and wrapped by KMS, or provided through
   a KMS data-key API?
4. What is the default decrypted-DEK cache lifetime?
5. Must KMS revocation take effect immediately, or is bounded cache expiry
   acceptable?
6. Is manual session unlock required in the first release?
7. What recovery modes are permitted, and who owns the recovery key?
8. How long may verified legacy ciphertext remain available for rollback?
9. What external state, if any, is used to detect storage rollback?
10. Which administrative OAuth scopes protect key configuration, migration,
    rotation, and recovery?

## Acceptance criteria

The feature is complete when:

- Every tenant credential uses a versioned envelope and a tenant-specific KEK.
- The COG database, S3 state, backups, and global master key are insufficient to
  decrypt a tenant's credentials without that tenant's key provider.
- One tenant key cannot decrypt or rebind another tenant's records.
- A tenant can independently revoke future decrypt access in its own KMS.
- OAuth callbacks, refresh, GitHub App use, and upstream calls fail closed when
  tenant decryption is unavailable.
- Migration and rotation are transactional, resumable, auditable, and verified.
- Agents require no encryption-specific behavior during normal operation.
- Documentation accurately states that protection applies at rest and that COG
  handles plaintext credentials in memory during authorized execution.
