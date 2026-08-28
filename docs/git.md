# Git smart HTTP

COG exposes repository remotes as `https://cog.example/git/<opaque-id>.git`. Git
pack traffic travels directly through the streaming `/git` proxy and never
passes through MCP or V8. Agents authenticate with Basic username `cog` and a
15-minute, repository-bound COG credential. The MCP bearer is used only to mint
or exchange that credential; Git never receives it.
Provider credentials are decrypted and used only inside COG.

The preferred setup path is the built-in GitHub App manifest flow. Call
`cog.github_app_setup_start` with a human-readable integration `name`, open the
returned one-time `browserUrl`, and complete the GitHub screens. COG posts an
App manifest requesting only `Contents: write`, receives the newly generated
App credentials at its callback, encrypts the PEM immediately, and redirects
the browser to installation and repository selection. GitHub then returns the
installation ID to COG and COG enables the integration. Use
`cog.github_app_setup_status` to inspect progress without exposing credentials.

The browser URL points to COG because GitHub's manifest entry requires an HTML
POST. Opening it renders an auto-submitting form; agents and link previewers
must not pre-open it. The setup token expires after 20 minutes. App creation and
installation are separate states, and repository access should be retried only
after status reports `installed`.

The callbacks are browser redirects, not inbound GitHub webhooks. The browser
must therefore be able to reach `COG_BASE_URL`. A public HTTPS origin works, as
does a private-network route or an SSH tunnel with a browser-reachable localhost
origin. A COG instance on an unreachable remote private address cannot complete
this automatic flow without adding a callback relay or copy-back fallback.

Manual fallback setup creates a `git` integration with configuration shaped like:

```json
{"kind":"git","provider":"github","host":"github.com","providerConfig":{"appId":"123","installationId":"456"}}
```

Submit the GitHub App PEM through the encrypted `privateKey` secret field. The
App should be installed only on selected repositories and have `Contents` read
and write permission. Do not use an OAuth client secret or put the PEM in the
configuration JSON.

If `repository_access` names a repository that is not selected for the App
installation, it returns `github_repository_installation_required` with a
`repositorySelectionUrl`. Open that URL, add the repository in GitHub, and
retry. GitHub App repository selection is the repository authorization boundary;
COG does not maintain a second per-client repository approval layer.

The built-in `git` code-mode catalog target provides `repository_access` and
`sealed_credentials`.
Calling it requires the agent's existing `integration:<id>` OAuth authorization.
Configure Git credentials with `credential.useHttpPath=true`; never embed a
credential in a remote URL. Provider branch protection and rulesets remain
responsible for pull-request, force-push, status-check, workflow, and
signed-commit policy.

Reverse proxies must disable request buffering and permit long-lived streaming
requests for `/git/`. Rotation is performed by updating the encrypted private
key. Disconnecting removes provider credentials while retaining the integration
authorization; deleting the integration removes both.

Install `git-credential-cog` beside `cog`, set `COG_GIT_ORIGIN` to the public
COG origin, and configure each COG remote:

```sh
git config credential.helper cog
git config credential.useHttpPath true
git clone https://cog.example/git/00000000-0000-0000-0000-000000000000.git
```

Never request or pass a plaintext Git password through MCP, tool arguments, a
shell command, or an interactive terminal. Prepare a one-use encryption request
with the helper:

```sh
git-credential-cog prepare https://cog.example/git/00000000-0000-0000-0000-000000000000.git
```

The command prints only a repository ID, ephemeral public key, and random
request nonce. Pass that JSON object to `sealed_credentials`, then feed the
returned encrypted JSON envelope to `git-credential-cog import` over standard
input. Do not put the envelope in command-line arguments. Import writes no
output, deletes the one-use private key, and stores the decrypted 15-minute
credential in its mode-0600 runtime file. The helper rejects expired requests,
unrelated origins, mismatched repositories, invalid Git paths, and modified
envelopes. A subsequent Git command receives the credential through Git's
private credential-helper pipe; the password is never returned to the MCP
client or agent transcript.

The non-secret controls are `COG_GIT_MAX_REQUEST_BYTES`,
`COG_GIT_MAX_RESPONSE_BYTES`, `COG_GIT_TIMEOUT_SECS`,
`COG_GIT_IDLE_TIMEOUT_SECS`, `COG_GIT_MAX_STREAMS`, and
`COG_GIT_MAX_STREAMS_PER_CLIENT`. `/metrics` reports
active streams, operations, denials, byte counts, upstream failures, and limit
rejections without client or repository labels.

For incident response, revoke the agent's integration or OAuth client access,
disable or disconnect the integration, change the GitHub App repository
selection, or rotate the App key and update COG's encrypted `privateKey`.
Configuration changes, disconnect, and deletion invalidate cached installation
tokens. JWTs and installation tokens are memory-only.

COG rejects upstream userinfo, fragments, redirects, and DNS answers in private,
loopback, link-local, multicast, or unspecified ranges. Explicit loopback HTTP
is reserved for controlled local provider tests.
