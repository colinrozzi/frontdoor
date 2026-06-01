# frontdoor — v0 design

**Owner:** frontdoor-dev@colinrozzi.com
**Status:** proposal awaiting Colin sign-off on architecture. TCP primitive sufficiency (§3) confirmed by theater-dev 2026-05-31.

## 1. Goals

frontdoor is a small Theater wasm actor that owns the VPS `:443` listener. For every inbound TLS connection, it:

1. Peeks the TLS ClientHello bytes,
2. Parses the SNI extension to extract the target hostname,
3. Looks up the hostname in a routing table (`hostname -> backend_addr`),
4. Opens an outbound TCP connection to the backend on loopback,
5. Forwards the buffered ClientHello bytes + every subsequent byte in both directions until either side closes.

Backends keep their own TLS termination — frontdoor never sees decrypted bytes.

This is the coordination point for `*.colinrozzi.com` HTTPS exposure. Today only `inbox-acceptor` is on `:443`. `tickets-ui`, `inbox-ui`, and future siblings all want to be reachable at `*.colinrozzi.com:443`, and without frontdoor each one would need its own public listener + cert juggling.

## 2. Non-goals (v0)

- **No TLS termination in frontdoor.** Each backend continues to own its own cert + crypto config. Frontdoor is a hostname-aware TCP router only.
- **No L7 inspection.** No HTTP-level routing, no header rewriting, no path-based dispatch. (SNI hostname is the only routing key.)
- **No cert provisioning.** Backends own their own certs (manual VPS provisioning is the v0 story; ACME automation is a separate later effort).
- **No load balancing.** One hostname maps to one backend address. No round-robin, no weighted dispatch.
- **No HTTP `:80` listener / ACME challenge proxying.** That's a v1 ask if we ever want frontdoor to mediate ACME for the backends.

A future v1 could add a TLS-termination mode if path-based routing or header inspection becomes valuable. Locked out of v0 to keep this lever clear.

## 3. Per-connection flow + TCP primitives

Theater-dev confirmed (2026-05-31): **current `crates/theater-handler-tcp` primitives are sufficient for SNI-router v0 — no new host functions required.** Bidirectional forwarding works via the existing `receive`/`send` primitives + active-mode callbacks.

### 3.0 TCP surface area (from `crates/theater-handler-tcp/tcp.pact`)

```
listen(addr) → listener_id
accept(listener_id) → connection_id        (PENDING state)
activate(conn)                              (passive by default once owned by actor)
send(conn, bytes) → bytes_written
receive(conn, max_bytes) → bytes            (empty = EOF)
connect(addr) → outbound connection_id
close(conn)
close-listener(listener_id)
set-active(conn, mode)                      ("active" | "once" | "passive")
transfer(conn, target_actor)                (hand connection to another actor)
upgrade-to-tls-server(conn)
upgrade-to-tls-client(conn, server_name)
peer-address(conn)
```

Notable for frontdoor: `connect(addr) → connection_id` is the outbound primitive (Q3.2 confirmed); `set-active(conn, "active")` flips a connection into callback-driven mode so the host dispatches `tcp-client.on-data` to the actor when bytes arrive (no actor-side polling); `transfer(conn, target_actor)` exists as a first-class primitive but frontdoor v0 doesn't use it (see §6).

### 3.1 SNI peek + forward (per inbound connection)

1. `accept(listener)` → `inbound` (PENDING state). `activate(inbound)`.
2. `receive(inbound, ~1500)` — pull the first chunk. ClientHello typically fits in 200-500 bytes, well under one MSS. Safety net: loop `receive()` if the chunk doesn't yet contain a complete record (bounded at 8 KiB / 5 reads — see §3.a).
3. Parse SNI from the buffered bytes (§3.a). On failure: `close(inbound)` and exit.
4. Lookup `backend_addr` in routing table. On miss: `close(inbound)` (or route to `default_backend` if configured).
5. `connect(backend_addr)` → `outbound`. On failure: `close(inbound)` and exit.
6. `send(outbound, buffered_bytes)` — the **replay** that substitutes for a literal peek. Backend now has the full ClientHello and proceeds with its own TLS handshake.
7. `set-active(inbound, "active")` + `set-active(outbound, "active")` — enter steady-state bidirectional bridging (§3.2). The buffered bytes live in actor memory, not kernel buffer; that's fine for handshake-sized data.

### 3.2 Steady-state bridging — active-mode callbacks (Option B)

Theater-dev offered two shapes:

- **Option A — passive, two loops:** spawn two tokio tasks per connection (one per direction), each looping `receive(src, N) → send(dst, data)`.
- **Option B — active mode, on-data callback:** `set-active(conn, "active")` + implement `tcp-client.on-data` to forward bytes to the peer. No actor polling loop.

Frontdoor v0 picks **Option B** — single-threaded reactive actor, no concurrent receive loops to manage from inside wasm, no per-direction task lifetimes to track. On each `on-data(conn, bytes)` callback, the actor looks up the peer connection id in `HashMap<connection_id, peer_connection_id>` state and calls `send(peer, bytes)`. Empty-bytes callback (EOF) triggers the close logic in §3.3.

Both options cross host↔wasm twice per chunk and are functional for v0. Splice (host-side zero-copy pump) is flagged as future work (§11).

### 3.3 Close semantics

- **EOF detection:** `receive()` returning an empty list (or active-mode `on-data` callback firing with empty bytes) is the signal the peer closed (or half-closed write side; the API doesn't distinguish).
- **Action on EOF from one side:** send any remaining buffered bytes on the peer, then `close(peer)`. Free the `HashMap` entry.
- **No half-close primitive.** `close(conn)` terminates both directions. For TLS-encrypted streams this is fine — the application protocol inside TLS handles its own connection framing, and TLS `close_notify` is the backend's concern (frontdoor never sees decrypted bytes). For raw protocols that depend on half-close, the current API can't express it; not a v0 problem (we only route TLS streams).
- **Backend connect failure:** drop the client immediately with `close(inbound)`. No retry, no buffering (see §5).

### 3.a SNI parse (in-actor)

Parsing the ClientHello to extract SNI is well-trodden; we'll do it manually in Rust without rustls (to keep the wasm small and avoid pulling crypto code into a connection that never decrypts).

Bytes-to-extract path (TLS 1.2/1.3):

```
[0]    record content type = 0x16 (handshake)
[1..3] record version (ignore)
[3..5] record length (u16 big-endian)
[5]    handshake type = 0x01 (ClientHello)
[6..9] handshake length (u24)
[9..11] client version
[11..43] random (32 bytes)
[43]   session_id length, then session_id bytes
       cipher_suites length (u16), then cipher_suites bytes
       compression_methods length (u8), then compression_methods bytes
       extensions length (u16), then extensions:
         each extension: type (u16) | length (u16) | data
         find type=0x0000 (server_name), parse SNI list, take first host_name
```

Practical: a single TCP read often delivers the whole ClientHello (~200-600 bytes for typical clients), but spec-wise we must loop `receive` until the record-length prefix is satisfied. v0 implements the loop; bound it at, e.g., 8 KiB or 5 reads to bail on adversarial/oversized hellos.

If SNI is absent (rare — TLS clients without SNI), frontdoor falls back to a configured `default_backend` if set, else closes the connection.

### 3.b Connection lifecycle — singleton actor with per-connection state

```
listener-actor (singleton; supervises nothing)
  state:
    listener_id
    routes: HashMap<hostname, backend_addr>
    default_backend: Option<backend_addr>
    pending: HashMap<connection_id, BufferState>          // mid-SNI-parse
    pipes:   HashMap<connection_id, connection_id>        // active = inbound→outbound and outbound→inbound

  on tcp.accept(listener_id) → inbound:
    activate(inbound); set-active(inbound, "active")
    pending[inbound] = BufferState { buf: Vec<u8> }

  on tcp-client.on-data(conn, bytes):
    if conn in pending:
      pending[conn].buf.extend(bytes)
      try parse SNI; on incomplete: continue; on parse fail: close(conn); del pending
      backend_addr = routes[sni] or default_backend or { close; return }
      outbound = connect(backend_addr) or { close(inbound); return }
      send(outbound, pending[conn].buf)
      set-active(outbound, "active")
      pipes[inbound] = outbound; pipes[outbound] = inbound
      del pending[conn]
    else if conn in pipes:
      if bytes.empty:                      // EOF
        peer = pipes[conn]; close(conn); close(peer)
        del pipes[conn]; del pipes[peer]
      else:
        send(pipes[conn], bytes)
```

## 4. Routing table

### 4.a Initial state — sentinel-seeded

frontdoor is deployed as a sentinel-managed sibling actor, same shape as inbox-acceptor + tickets-acceptor. Sentinel provides initial state as a TOML/JSON blob:

```toml
# initial_state.toml (sentinel-rendered)
default_backend = "127.0.0.1:8443"  # optional; if unset, no-SNI = close

[[route]]
hostname = "mail.colinrozzi.com"
backend  = "127.0.0.1:8443"

[[route]]
hostname = "tickets.colinrozzi.com"
backend  = "127.0.0.1:8444"

[[route]]
hostname = "inbox.colinrozzi.com"
backend  = "127.0.0.1:8445"
```

No wildcards in v0. Exact-hostname match only. Wildcard support (`*.colinrozzi.com -> X`) is a small v1 follow-up — defer until we have ≥2 hostnames that genuinely want it.

### 4.b Live updates — TCP command channel

frontdoor binds a second listener on a control port (loopback only, e.g. `127.0.0.1:9100`) accepting newline-delimited JSON commands:

```json
{"op": "upsert_route", "hostname": "tickets.colinrozzi.com", "backend": "127.0.0.1:8444"}
{"op": "delete_route", "hostname": "tickets.colinrozzi.com"}
{"op": "set_default",  "backend": "127.0.0.1:8443"}
{"op": "list_routes"}
```

Why a TCP command channel and not just "redeploy frontdoor when routes change"? Routes will change every time we add a backend or move one; redeploying the public `:443` listener every time risks dropping in-flight connections + adds operational pain. The TCP control channel is the same shape sentinel-dev established for live config updates elsewhere; coordinate with them on the exact wire format (probably JSON-over-TCP matching what sentinel-acceptor's update-route ops look like).

Theater-dev's recommended v0 was static-only ("routing table: static manifest config for v0; iterate to dynamic via TCP command in v1") — smaller v0 surface, no second listener, no JSON parser. Keeping dynamic in v0 because CLAUDE.md item 5 locks it as a Colin-stated architectural constraint, and it's the difference between "frontdoor solves the deploy pain" and "frontdoor adds a redeploy step every time a backend hostname changes." Colin can rule on PR review if the simpler v0 is preferred.

In-flight connections are unaffected by route changes — once a connection is in `pipes` (steady-state forwarding, §3.b), its peer connection id is fixed; the routing table is only consulted at SNI-parse time. A live `upsert_route` only changes routing for newly-accepted connections.

## 5. Multi-backend health & failure

Three sub-cases on the outbound connect:

1. **Backend up, accepts.** Happy path. Pipe.
2. **Backend down (connect refused / timeout).** Frontdoor closes the client immediately. No retry, no buffering. The TLS client sees a TCP reset and reports a connection error; their retry logic is unchanged.
3. **Backend up, then disappears mid-stream.** Either side EOFs (active-mode `on-data` with empty bytes); frontdoor closes the other and frees both `pipes` entries (§3.b/§3.3).

**No active health checks in v0.** The backend either accepts the loopback TCP connect or it doesn't; that's our health signal. Active checks (ping every Ns, mark down on failure, fast-fail subsequent connects) are a v1 quality-of-life feature — defer until we observe the v0 behavior is actually painful.

**No backend retries.** If `127.0.0.1:8443` refuses, the client retries the public `:443`; frontdoor will try again on the next ClientHello and likely succeed if the backend came back. No internal retry, no exponential backoff, no circuit-breaker — these all add complexity that doesn't pay off until we have measured failure modes.

## 6. Actor model — singleton with active-mode callbacks

**v0 picks the singleton model.** One frontdoor actor binds `:443`, owns the listener, and handles all connections through active-mode callbacks. State is the `pending` + `pipes` `HashMap`s sketched in §3.b. No child actors are spawned per connection.

Considered and rejected for v0 — per-connection child actor (one actor instance per inbound TLS connection, using `transfer(conn, child)` to hand the accepted socket over). Theater-dev: "pick based on isolation taste; chain-bounding work covers either choice." Two reasons singleton wins for v0:

1. **Chain-growth pragmatism.** Per-connection actor under sentinel introduces the grandchild-supervisor-recording amplification theater-dev diagnosed: `sentinel ← frontdoor-listener ← conn-actor`, with each `handle-child-event` invocation recorded as a `wasm-call` chain entry on every level. Singleton eliminates that amplification entirely — frontdoor has only its own chain + the existing one-level bubble-up into sentinel. Until chain-eviction (Tier 1) and `record_child_events = false` (Tier 3) ship, singleton is strictly safer.
2. **Smaller v0 surface.** Singleton is one actor entrypoint, one manifest, one supervised process. Per-connection requires modeling actor spawn/teardown + handling `transfer()` semantics. Both are shippable, but per-connection is more work for v0.

**v1 path** — refactor to per-connection child actor for better isolation (a bug in handling one connection can't corrupt the pipes table for others) once **both** of these land:
- Theater chain-eviction (Tier 1) — bounds per-actor chain memory.
- Theater `record_child_events = false` manifest knob (Tier 3) — frontdoor listener can flip this on its own supervisor handler, eliminating grandchild amplification into its chain. Sentinel sets the same flag on its handler for frontdoor.

Both are in theater-dev's plan but blocked on Colin's "repro first" call (§6.a). Re-evaluate when the chain-bounding work ships.

### 6.a Chain-growth context

Singleton means frontdoor contributes only its own chain to the system, not a tree. The wedge-amplification diagnosis below still drives the design — it's why singleton is the v0 choice — but the concrete chain-bounding configuration is much simpler than the earlier per-connection-actor draft assumed.

#### 6.a.i Theater-dev's diagnosis (2026-05-31)

Manager flagged a wedge-root-cause hypothesis: sentinel's chain-file on the VPS accumulates ~50MB/min, and a 2.9GB in-memory chain is plausibly causing the daily wedge. Theater-dev surveyed the chain paths and confirmed the mechanism + landed a concrete fix plan:

**Root cause** — `StateChain.events: Vec<ChainEvent>` (`crates/theater/src/chain/mod.rs:255`) grows for the life of the actor with no bound. ChainWriter already streams every event to disk, so the in-memory Vec is redundant for durability; it exists for `verify()` / `get_events()`.

**Amplification** — sentinel doesn't actually subscribe to grandchildren; it's a RECORDING amplification: when a child invokes `handle-child-event`, the runtime records the call as `wasm-call("handle-child-event", child_id, event_type, X.data)` with the grandchild's payload embedded. That recorded event bubbles up through each supervisor level, embedding the prior level's embedded payload — three-level nesting per delivery.

**Theater-dev's fix plan:**

- **Tier 1 (this week, ~150 LOC + tests):** per-actor config `chain.in_memory_max_events`, default unbounded for back-compat. Evicts from front of Vec when exceeded. Disk-side ChainWriter unchanged.
- **Tier 2 (couple weeks, breaking chain format change):** stop embedding child-event payloads in supervisor's wasm-call params. Chain entry references `(child_id, event_type, event_hash)` only; child's chain holds the payload. Collapses parent growth from O(events × payload × depth) to O(events × depth).
- **Tier 3 (manifest knob, after tier 2):** `[handler.supervisor] record_child_events = false`. Supervisor still invokes the callback; runtime doesn't record the invocation. Zero-overhead for supervisors that use `handle-child-event` to react (e.g. sentinel reacting to crashes), not to audit.

#### 6.a.ii Frontdoor's chain-bounding configuration

Because frontdoor is singleton (no per-connection child actors), there's no nesting amplification within frontdoor — only the one-level bubble-up into sentinel that any supervised actor produces. Two configurations matter:

1. **`chain.in_memory_max_events`** on frontdoor's manifest, once Tier 1 ships. Suggested bound: **65536 events** — covers an accept-event cadence on the order of tens of thousands per day before eviction kicks in. Disk chain is unbounded as today.
2. **`[handler.supervisor] record_child_events = false`** on sentinel's supervisor handler for frontdoor, once Tier 3 ships. Sentinel's interest in frontdoor is "did it crash", not "audit every TLS connection." Eliminates frontdoor's contribution to sentinel chain growth.

Until Tier 1 lands, the v0 deploy carries the risk that high connection volume forces unbounded chain growth in frontdoor's in-memory Vec. Mitigation: watchdog auto-restart on frontdoor's RSS (same shape as the sentinel watchdog), as a temporary stopgap. The watchdog is operationally cheap because frontdoor's restart cost is "drop in-flight TLS connections, clients retry."

**Status (2026-05-31):** Colin has asked theater to hold Tier 1/2/3 until a clean repro of the wedge is in hand. The frontdoor v0 design above is _conditional on those fixes eventually landing_ — interim deploy uses watchdog stopgap. If repro changes the root-cause picture, the singleton-vs-per-connection decision may swing back, but neither direction blocks shipping v0 today.

## 7. ACME / cert provisioning

**Out of scope for v0.** Backends own their certs; v0 deploys assume:

- `inbox-acceptor` already has its own cert mounted (today's behavior).
- `tickets-ui`, `inbox-ui`, etc. will each ship with their own cert mount, matching the inbox-acceptor pattern.
- Manual `certbot` on the VPS provisions all certs initially. We accept the operational cost of re-running certbot per backend per renewal cycle.

Open question for v1: do we want frontdoor (or a sibling `acme-acceptor` actor) to own `:80` for HTTP-01 challenges and dispatch challenge responses on behalf of all backends? That would centralize cert provisioning. Not in scope here; flag for follow-up.

## 8. Cutover from "inbox-acceptor owns :443"

Today: `inbox-acceptor` binds `:443` directly. Frontdoor swap-in requires:

1. inbox-acceptor moves to a loopback port (e.g. `127.0.0.1:8443`), keeping its TLS termination + cert exactly as-is. This is a one-line listener-address change in inbox-acceptor's manifest; no TLS code changes.
2. frontdoor deploys, binds `:443`, with initial routing table `mail.colinrozzi.com -> 127.0.0.1:8443`.
3. We accept the cutover instant: any in-flight `:443` connection at the moment inbox-acceptor unbinds is dropped. Clients retry; the retry hits frontdoor → backend.

This is the same shape as the recent "put inbox under sentinel" cutover ([[project_inbox_cutover_lessons]]) — coordinate with `inbox-dev` and `sentinel-dev` on the deploy sequencing closer to the time. **Not driving that coord now** — design first, then build the actor, then plan the cutover.

## 9. Actor decomposition & build

- One Rust crate `frontdoor` building one wasm component. One entrypoint (no spawn-arg branching). Singleton actor per §6.
- One sentinel-rendered manifest `frontdoor.manifest.toml` consumed by sentinel-acceptor as a sibling actor.
- `flake.nix` building the wasm via `nix build`, matching the pattern used by inbox-acceptor / tickets-acceptor flakes.
- Dependencies: `packr-guest` only (per [[inbox-deps-no-theater-crate]] — guests don't depend on the `theater` crate; the host is host-side).
- SNI parsing: hand-rolled (~100 LOC for the extension walk) to avoid pulling rustls's full ClientHello parser + transitive crypto code into a connection that never decrypts. Theater-dev confirmed rustls has a standalone ClientHello parser available, but the dependency cost isn't worth it for ~100 LOC of well-trodden TLS record parsing.
- No `serde_json` or heavy JSON parsing if we can avoid it — the routing-table TOML can be parsed with `toml` (small), and the live-update command channel (§4.b) uses a minimal hand-rolled JSON parser. Will measure before deciding if `serde_json` is acceptable.

Build + deploy:

- Repo: `colinrozzi/frontdoor`. PRs via auto-merge squash; this repo has `allow_auto_merge=true` (verify on PR #1, follow [[feedback-gh-auto-merge-silent-noop]] if not).
- Release: nix-build → wasm artifact published as GitHub release (or fetched directly from the repo via theater's `https://` manifest support, per [[sentinel-phase2-scope]]).
- Sentinel renders the live manifest with route-table initial state, and brings frontdoor up as a managed sibling.

## 10. Scope cuts (what we are NOT building in v0)

- No HTTP `:80` listener (no ACME challenge proxying, no HTTP-to-HTTPS redirect for the world).
- No TLS termination of any kind. (Lever held; explicitly v1+.)
- No wildcard SNI matching (`*.colinrozzi.com`).
- No active backend health checks.
- No internal retries on backend connect failures.
- No per-route rate limiting / per-IP rate limiting.
- No structured access logging beyond Theater's actor-level event log. (Hostname + backend_addr for each connection is plenty for v0.)
- No metrics emission. (Add a `theater:simple/metrics` integration in v1 once it exists.)

## 11. Open follow-ups (post-v0)

- **`splice(in, out)` host primitive** — bidirectional host-side byte pump, no wasm round-trips per chunk. Theater-dev estimates ~150 LOC in `theater-handler-tcp` + new function in `tcp.pact`. Big perf win for a router under load; ship v0 first, profile, add splice if host↔wasm crossings show up as the bottleneck.
- **Per-connection child actor refactor** — once Tier 1 chain-eviction + Tier 3 `record_child_events = false` ship, refactor singleton → per-connection child via `transfer(conn, child)`. Gains isolation (a bug in one connection can't corrupt the singleton's pipes table). §6 documents the criteria.
- **Half-close primitive (`shutdown-write(conn)`)** — only if a routed protocol surfaces a need. Current API closes both directions, which is fine for TLS-encrypted streams.
- Wildcard SNI routes.
- Active backend health checks + fast-fail.
- `:80` listener for ACME HTTP-01 dispatching, possibly enabling centralized cert provisioning.
- TLS-termination mode for backends that don't want their own cert juggling.
- Per-connection rate limiting / abuse defense.
- Structured access logging (per-connection record into Theater event store).

## 12. Risks

- **Chain-growth wedge.** Until theater Tier 1 chain-eviction ships, an attacker who can open many TLS connections forces unbounded chain growth in frontdoor's in-memory Vec. Mitigation: watchdog auto-restart on RSS as an interim stopgap (§6.a.ii). The wedge is gated on Colin's "repro first" call; if repro changes the picture, §6.a may need revisiting, but the v0 design (singleton + watchdog) ships either way.
- **Cutover from `inbox-acceptor` owning `:443`.** The swap drops in-flight TLS connections at the moment inbox-acceptor unbinds. Mitigation: schedule during low-traffic window, coordinate with inbox-dev and sentinel-dev. Not driving that coord now — design ships first.
- **Adversarial ClientHellos** (intentionally fragmented, oversized, malformed) could DoS the SNI-parsing path. Mitigation: bound buffer size + read-count, close on parse failure, log + move on (§3.a).
- **Singleton blast radius.** A bug in the SNI parser or pipe state machine takes down all in-flight connections, not just one. Mitigation: per-connection child actor refactor in v1 once Tier 1 + Tier 3 land (§11). Until then, the trade is "smaller v0 surface + bounded chain" vs "isolation."
- **`HashMap` lookup cost per `on-data` callback.** Constant-factor; not a v0 concern. If host↔wasm crossings dominate before this does, we'll have switched to `splice()` anyway (§11).

— end —
