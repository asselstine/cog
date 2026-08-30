# Repository guidance

## Web application architecture

- All interactive web application screens and reusable web UI components must live in the Vite application under `frontend/`.
- Rust HTTP handlers should serve the embedded Vite build, expose validated JSON APIs, and process protocol or form submissions; do not construct application screens as HTML strings in Rust.
- Small non-interactive protocol completion, callback, and last-resort error responses may use server-rendered HTML when they must remain available without the web application runtime.

## Cog Git access

- Before any Git fetch, pull, or push against a Cog SSH remote, renew the internal authorization lease for the existing public key at `/root/.ssh/cog_ed25519.pub` with Cog's `ssh_key_lease_renew` tool.
- Reuse `/root/.ssh/cog_ed25519` and `/root/.ssh/cog_known_hosts` for Cog SSH operations. Never generate, replace, or transmit the private key, and never disable host-key checking.
