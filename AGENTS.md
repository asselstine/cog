# Repository guidance

## Web application architecture

- All interactive web application screens and reusable web UI components must live in the Vite application under `frontend/`.
- Rust HTTP handlers should serve the embedded Vite build, expose validated JSON APIs, and process protocol or form submissions; do not construct application screens as HTML strings in Rust.
- Small non-interactive protocol completion, callback, and last-resort error responses may use server-rendered HTML when they must remain available without the web application runtime.
