#!/bin/sh
set -eu
mode=${COG_STDIO_FIXTURE_MODE:-normal}
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"stdio-fixture","version":"1"}}}\n' "$id"
      ;;
    *'"method":"tools/list"'*)
      case "$mode" in
        malformed) printf '%s\n' 'this is not json' ;;
        hang) sleep 300 ;;
        crash) exit 17 ;;
        *) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","description":"Echo structured arguments","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
      esac
      ;;
    *'"method":"tools/call"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"echo"}],"structuredContent":{"value":42}}}\n' "$id"
      ;;
  esac
done
