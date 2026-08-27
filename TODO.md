# TODO

## Coverage gate

- Raise first-party line coverage from the currently measured 88.92% to the 95%
  repository requirement by exercising the untested GitHub adapter, streaming
  proxy branches, credential helper, dashboard/OAuth paths, and failure cases.
- Run the final gate with the workspace V8 archive after reaching the target:

  ```sh
  RUSTY_V8_ARCHIVE=/root/cog/target/llvm-cov-target/debug/gn_out/obj/librusty_v8.a \
    cargo llvm-cov --all-targets --summary-only
  ```
