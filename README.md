# frontdoor

Theater-native TLS-aware front-door for the colinrozzi.com actor ecosystem.

Owned by **frontdoor-dev@colinrozzi.com**.

A small Theater wasm actor that binds the VPS `:443` listener, peeks the
SNI extension out of each incoming TLS ClientHello, looks the hostname
up in a routing table, and forwards the raw encrypted TCP stream to the
appropriate backend (`inbox-acceptor`, `tickets-acceptor`,
`inbox-ui`, …) over loopback. Backends keep their existing TLS
termination — frontdoor is a hostname-aware TCP router, not a TLS
terminator.

See [`DESIGN.md`](./DESIGN.md) for the v0 architecture (Colin-signed
2026-06-02, merged via PR #1).

## Layout

```
src/
  lib.rs    — actor entrypoints + state machine
  sni.rs    — hand-rolled TLS ClientHello SNI parser
manifest.toml — template manifest (sentinel renders the live one)
flake.nix     — `nix build` → frontdoor.wasm
```

## Build

```sh
nix build                       # produces ./result/frontdoor.wasm
```

## Routing — initial state

Sentinel passes a JSON blob as `initial_state` at spawn time:

```json
{
  "default_backend": "127.0.0.1:8443",
  "routes": [
    { "hostname": "mail.colinrozzi.com",    "backend": "127.0.0.1:8443" },
    { "hostname": "tickets.colinrozzi.com", "backend": "127.0.0.1:8444" },
    { "hostname": "inbox.colinrozzi.com",   "backend": "127.0.0.1:8445" }
  ]
}
```

Both fields are optional. If `default_backend` is empty and a
ClientHello carries no SNI (or names a hostname with no matching
route), the connection is dropped.

## Routing — live updates

`127.0.0.1:9100` accepts newline-delimited JSON commands:

```
{"op":"upsert_route","hostname":"tickets.colinrozzi.com","backend":"127.0.0.1:8444"}
{"op":"delete_route","hostname":"tickets.colinrozzi.com"}
{"op":"set_default","backend":"127.0.0.1:8443"}
{"op":"list_routes"}
```

The control listener is bound to `127.0.0.1` only, so the security
boundary is "anything that can talk to loopback can rewrite routes."
In-flight connections are unaffected by route changes — the routing
table is consulted only at SNI-parse time.
