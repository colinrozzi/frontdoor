# frontdoor — v0 design

**Owner:** frontdoor-dev@colinrozzi.com
**Status:** v0 shipped (PRs #1–#5, releases through `release-20260605-63d75f2`); pivoting actor-model to **per-connection child actor** after 2026-06-07 cutover stall. Subscription opt-out shipped 2026-06-08 (theater 0.3.25 / theater-handler-supervisor 0.3.16 — §6.c.i). **Per-conn-child implementation now gated on a new TCP-handler FD-handoff primitive that doesn't exist yet (§6.c.ii)** — Colin call. See §6 for the new shape, §6.a for the stall analysis. Sections marked **[v0 superseded]** describe the original singleton model that the §6 pivot replaces.

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
upgrade-to-tls-server(conn)
upgrade-to-tls-client(conn, server_name)
peer-address(conn)
```

Notable for frontdoor: `connect(addr) → connection_id` is the outbound primitive (Q3.2 confirmed); `set-active(conn, "active")` flips a connection into callback-driven mode so the host dispatches `tcp-client.on-data` to the actor when bytes arrive (no actor-side polling).

**FD-handoff is NOT currently a primitive** (theater-dev 2026-06-08): "The tcp handler owns its listener and yields connections to the same actor that called accept; 'transfer to a child' needs design we don't have yet." An earlier version of this section listed `transfer(conn, target_actor)` — that was incorrect. A `hand-off-connection(conn-id, target-actor-id)` primitive (or equivalent — semantics TBD) is the actual gate on §6 per-conn-child implementation. See §6.c for the current ask to theater-dev.

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

### 3.b Connection lifecycle — singleton acceptor + per-connection child actor

Per §6, frontdoor v1 splits across two actors: a **singleton acceptor** that owns the listeners + route table + control channel, and a **per-connection child actor** spawned for every accepted TCP connection. The acceptor never sees the connection's bytes; the child does the SNI peek, backend connect, and bidirectional bridge.

```
frontdoor-acceptor (singleton; supervisor of all per-conn children)
  state:
    public_listener_id
    control_listener_id
    routes: HashMap<hostname, backend_addr>
    default_backend: Option<backend_addr>
    children: Set<actor_id>                  // for spawn/exit accounting only

  on tcp.accept(public_listener_id) → inbound:
    child_init = { conn_id: inbound, routes: snapshot(routes), default_backend }
    child = supervisor.spawn-detached(per-conn-manifest, child_init)   // see §6.c
    transfer(inbound, child)                  // hand connection ownership over
    children.insert(child)

  on tcp.accept(control_listener_id) → control_conn:
    activate(control_conn); set-active(control_conn, "active")
    // control connections stay on the singleton — small volume, route mutations
    pending_control[control_conn] = BufferState { buf: Vec<u8> }

  on tcp-client.on-data(control_conn, bytes):
    accumulate + dispatch newline-delimited JSON; mutate `routes` / `default_backend`.

  on supervisor.on-child-exit(child):
    children.remove(child)
    // No per-connection chain event has flowed through the acceptor's chain
    // because the spawn opted out of subscription (§6.c). The only chain
    // entries from this connection are the spawn + the exit notification.

frontdoor-conn (one instance per inbound TCP connection; exits on EOF)
  init(child_init):
    state = { conn_id, routes, default_backend, buf: Vec<u8>, outbound: None }

  on tcp-client.handle-connection(conn_id):   // fires after transfer
    activate(conn_id); set-active(conn_id, "active")

  on tcp-client.on-data(conn, bytes):
    if outbound.is_none():
      buf.extend(bytes)
      match sni::parse(&buf):
        Incomplete -> wait for more bytes (bounded by PENDING_BUFFER_CAP)
        Found(host) -> backend = routes[host] or default_backend or { exit }
                       outbound = tcp.connect(backend) or { exit }
                       set-active(outbound, "active")
                       send(outbound, buf); buf.clear()
        Absent     -> backend = default_backend or { exit }; same connect+replay path
        Malformed  -> exit
    else:
      // mid-stream byte; forward to peer
      peer = (conn == inbound) ? outbound : inbound
      send(peer, bytes) or { exit }

  on tcp-client.on-close(conn, reason):
    close the peer if open; actor exits.
```

The per-conn child's state is small and dies with the actor; no `HashMap` of pipes, no `Vec` of pending, just two `connection_id`s and a buffer. The acceptor's state is the route table + the small `children` set.

#### 3.b.i What stays on the acceptor

- Both listeners (`public` + `control`).
- The route table and `default_backend`.
- Control-channel state machine (newline-delimited JSON, route mutations).
- The supervised set of per-conn children, only for liveness accounting.

#### 3.b.ii What moves to the per-conn child

- The SNI parse + the buffered ClientHello bytes.
- The outbound `tcp.connect` to the backend.
- Active-mode `on-data` bidirectional forwarding.
- All `tcp_close` calls for the inbound + outbound pair.

#### 3.b.iii Route snapshot semantics

The child receives a **snapshot** of the routes at spawn time via `init_state`. In-flight connections are unaffected by live `upsert_route` / `delete_route` commands — once a connection is alive on a per-conn child, its routing lookup uses the snapshot it was spawned with. This matches the v0 in-flight semantics in §4.b and keeps the child genuinely independent of the acceptor mid-stream. Subsequent accepts spawn children with the freshly-mutated snapshot.

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

## 6. Actor model — singleton acceptor + per-connection child

**v1 (current) picks the per-connection child model**, after the 2026-06-07 cutover reproduced the chain-growth wedge under TCP load (§6.a). One singleton **acceptor** owns the public listener + control listener + route table. Every accepted public TCP connection spawns a **per-connection child** that owns the SNI peek + backend connect + bidirectional bridge for that one connection, and exits when the connection tears down.

The acceptor opts out of subscribing to the per-conn children's chain events (§6.c) so:
- the child's per-connection chain (tcp events, sni parse, etc.) never flows into the acceptor's chain via `handle-child-event` recording;
- the acceptor's own chain only records `spawn child X` + `child X exited` per connection — tiny payloads, ~hundreds of bytes;
- sentinel only sees the acceptor's small chain, not the high-volume per-conn chains.

### 6.0 What the per-conn child split buys vs. the singleton model

| concern | singleton (v0, superseded) | per-conn child (v1) |
|---|---|---|
| acceptor chain growth per connection | 4–8 chain entries (accept, on-data ×N, connect, on-close), payloads include forwarded byte chunks | 2 chain entries (spawn, exit), constant payload |
| crash blast radius | bug in one conn corrupts singleton's `pipes`/`pending` HashMaps → all in-flight conns dropped | bug in one conn kills only that child; acceptor + other children unaffected |
| state size in acceptor | O(in-flight conns) | O(in-flight children) entries in `children` set (no per-conn buffers / pipes) |
| code path under load | one actor handles all on-data callbacks serially | per-conn actors run independently; backend latency on one conn doesn't head-of-line block others |
| extra cost | n/a | per-accept actor spawn/teardown (wasm component init + manifest fetch — fetch is cached, init is ~ms order) |
| new theater capability needed | none | opt-in subscription (shipped 2026-06-08 in theater 0.3.25) + FD-handoff primitive (not yet — §6.c.ii is the actual blocker) |

The per-conn cost is the only real downside, and it pays off the moment a connection storm appears (which is exactly what reproduced the wedge — see §6.a).

### 6.a The 2026-06-07 cutover stall — wedge reproduced under load

Phase 2 of the prod cutover (sentinel takes over `:443` with frontdoor singleton in front of inbox-acceptor) stalled reproducibly under TCP load. A brief connection storm to the public `:443` listener (single IP, 100+ TCP connections in ~2 min, classifier shape) generated enough chain events on frontdoor's singleton chain that sentinel's subscriber couldn't drain the channel. Producer back-pressure then stalled the actor tree: mailbox-router's spawn loop, etc.

This converts §6.a (formerly hypothetical, gated on Colin's "repro first" call) into a confirmed mechanism: the singleton model channels per-connection traffic through a single chain that is exactly the kind of high-throughput producer the chain-amplification path can't keep up with. Per-conn child model breaks the amplification at the source — each child is its own chain, ephemeral, and crucially **unsubscribed by the parent**, so the recording amplification (parent's chain recording `wasm-call("handle-child-event", child_id, X.data)` with `X.data` embedded) is eliminated by construction.

Phase 1 (new theater + new sentinel without frontdoor cutover) is live. Phase 2 was rolled back; the cutover proper waits on this redesign.

#### 6.a.i Theater-dev's earlier diagnosis — still load-bearing

The chain growth + amplification mechanism theater-dev described 2026-05-31 still drives this design: `StateChain.events: Vec<ChainEvent>` grows unbounded; supervisor's `handle-child-event` recordings embed the grandchild payload at each level, producing three-level nesting per delivery. The per-conn-child + opt-out-subscription combination is the structural fix, not a workaround.

(Tier 1 chain-eviction + Tier 3 `record_child_events = false` from theater-dev's earlier three-tier plan are still useful as defense-in-depth — they bound chain memory and remove parent recording in cases where opt-out isn't an option. But the v1 frontdoor design doesn't depend on them; it sidesteps the amplification entirely.)

### 6.b [v0 superseded] singleton model + chain-bounding configuration

(Retained for context; the v1 §6/§6.a above replaces this analysis. The §6.b.i chain-bounding configuration only matters if a v2 ever wants the singleton back.)

Until 2026-06-07, the v0 design picked the singleton model for two reasons:
1. **Chain-growth pragmatism** under the singleton-vs-per-conn trade — at v0 design time, the wedge mechanism was hypothesized but unreproduced, and the per-conn refactor depended on theater Tier 1 + Tier 3 landing.
2. **Smaller v0 surface** — one actor entrypoint, one manifest, no `transfer()` / spawn lifecycle modeling.

The 2026-06-07 cutover stall flipped both of these. The amplification reproduced (so chain pragmatism now argues *for* per-conn, not against it), and the opt-in subscription work theater-dev is doing makes the per-conn spawn API a viable path without waiting on Tier 1 / Tier 3.

#### 6.b.i Singleton chain-bounding configuration (if ever revived)

1. `chain.in_memory_max_events` on frontdoor's manifest, once Tier 1 ships. Suggested bound: 65536 events. Disk chain unbounded as today.
2. `[handler.supervisor] record_child_events = false` on sentinel's supervisor handler for frontdoor, once Tier 3 ships.

Both are in theater-dev's plan but were blocked on Colin's "repro first" call at v0 design time. (Repro happened 2026-06-07; the response is the §6 pivot, not a singleton patch.)

### 6.c Theater-dev API: opt-in subscription (SHIPPED) + FD-handoff (NEW GATE)

Two distinct theater-side dependencies. Subscription opt-out is shipped as of theater 0.3.25 / theater-handler-supervisor 0.3.16; connection handoff is the remaining gate on implementation.

#### 6.c.i Opt-in subscription — theater 0.3.25 (shipped 2026-06-08)

Theater PR #108 + release #109 made child-event subscription opt-IN by default. Previously `spawn` attached a parent subscriber automatically; now it doesn't. Parents that want chain events call (post-spawn, per child):

```
subscribe-to-child:     func(child-id: string) -> result<_, string>
unsubscribe-from-child: func(child-id: string) -> result<_, string>
```

Both idempotent; error if `child-id` isn't tracked by the calling supervisor. For frontdoor: acceptor spawns, never subscribes — done. No new spawn arg, no `record_child_events=false` knob needed.

Maps onto the earlier (a)–(e) questions:

- **(a) API shape** — neither variant; subscription is post-spawn host calls, not a spawn arg. Frontdoor's per-conn case is the trivial "spawn, never subscribe" path.
- **(b) Recording amplification eliminated by construction.** With no subscriber, the dispatch loop never enters the `.send().await` path for the parent, so `handle-child-event` never fires on the parent, so the parent's chain has no `wasm-call("handle-child-event", ..., child-event-data)` to record. No separate knob needed.
- **(c) Lifecycle events ride a separate always-on channel** (`handle-child-error`, `handle-child-exit`, `handle-child-external-stop` via the `ActorResult` channel). Opt-in subscription only gates `handle-child-event`. Acceptor's exit accounting (`children: Set<actor_id>`) works regardless of subscription state. ✓
- **(e) Chain is in-memory only post-PR #105.** Events dispatched and dropped; no `chains/{actor_id}.chain` on disk by default. Per-conn children with no subscriber and no replay handler produce zero disk accumulation. The §11 follow-up about per-conn chain GC is **removed** — there is no GC problem to solve.

#### 6.c.ii FD-handoff — NOT a current primitive (the actual blocker)

Theater-dev 2026-06-08: "FD transfer between actors isn't a current primitive. The tcp handler owns its listener and yields connections to the same actor that called accept; 'transfer to a child' needs design we don't have yet. This is a Colin call — likely a new host function on `theater:simple/tcp` (something like `hand-off-connection(conn-id, target-actor-id)`), with semantics for whether the target receives it via a special init param, a callback handler, or a queued message."

Implication: the §3.b "acceptor accepts → spawns child → transfers conn" sketch cannot be implemented today. The accepted connection is bound to the acceptor's actor identity; there is no primitive that gives a child actor ownership of a connection accepted by its parent.

**Options on the table** (all need theater-dev / Colin design input):

1. **New primitive `hand-off-connection(conn-id, target-actor-id)`** on `theater:simple/tcp`. Cleanest for frontdoor. Semantics question (for theater-dev / Colin): does the target receive the connection (a) via a new init param at spawn time, (b) via a new callback handler (e.g. `tcp-client.handle-handed-off-connection`), or (c) via a queued tcp-client.handle-connection like a fresh accept? Each has its own state-machine implications on the child side.
2. **Child-side `accept` on a per-conn listener.** Acceptor binds the public `:443` listener, but each accept handed back returns enough info that the acceptor can spawn a child that performs its OWN `accept` somehow against that connection. Probably doesn't fit theater's actor model cleanly.
3. **Acceptor stays in the bytes path, but spawns per-conn children that only do CPU work** (SNI parse, route lookup). Acceptor handles all I/O. *This DOESN'T solve the chain-amplification problem* — the acceptor's chain still records every on-data callback for every byte chunk on every connection. Rejected.

Option 1 is the only one that actually delivers the §6 design goal (acceptor's chain only sees spawn+exit, never per-byte events). Frontdoor's implementation is blocked until that primitive — or an equivalent — exists.

#### 6.c.iii Status / next steps

- **Subscription opt-out: done.** Once theater 0.3.25 is in the flake, the acceptor just doesn't call `subscribe-to-child` after its spawns.
- **FD-handoff primitive: needs design.** Escalating to manager + Colin as the gating ask, since theater-dev flagged it's not in their lane — it's a "design we don't have yet" call.
- **PR #6 (this DESIGN doc) stays draft** until the FD-handoff primitive design lands. The §3.b sketch is conditional on whichever Option 1 sub-variant Colin picks; once that's known, §3.b can be tightened to match the actual host-side semantics (init-param vs. callback vs. queued accept).

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

v1 splits the Rust workspace into **two crates** producing **two wasm components**:

- `frontdoor-acceptor` — the singleton. Owns both listeners, the route table, the control channel, and the supervisor of per-conn children. No `tcp_connect`, no SNI parsing, no on-data forwarding — these all moved to the child.
- `frontdoor-conn` — the per-connection child. One instance per accepted public TCP connection. Receives the transferred conn + route snapshot via `init_state`, does SNI peek, backend connect, bidirectional bridge, exit. No listener, no control channel, no route mutation.

Each crate's `lib.rs` ABI is small and disjoint: the acceptor exports `init`, `tcp-client.handle-connection` (control listener accepts only), `tcp-client.on-data` (control bytes), `tcp-client.on-close` (control), `supervisor.on-child-exit` (per-conn child lifecycle). The per-conn child exports `init` + the three `tcp-client.*` callbacks.

Two manifests:

- `frontdoor-acceptor.manifest.toml` — sentinel-rendered, consumed by sentinel as a sibling actor.
- `frontdoor-conn.manifest.toml` — referenced from `frontdoor-acceptor.manifest.toml` via theater's `package = "https://..."` mechanism (per [[sentinel-phase2-scope]]). The acceptor passes the per-conn-child manifest URL through to `supervisor.spawn` calls. No separate sentinel renderable for the child — its config comes from `init_state` per spawn.

`flake.nix` builds both wasm components in one invocation. Release artifacts: `frontdoor_acceptor-<tag>.wasm` + `frontdoor_conn-<tag>.wasm` alongside the existing `frontdoor.template.toml` (renamed `frontdoor-acceptor.template.toml`).

- Dependencies on both crates: `packr-guest` only (per [[inbox-deps-no-theater-crate]] — guests don't depend on the `theater` crate; the host is host-side).
- SNI parsing now lives in `frontdoor-conn`. Same hand-rolled parser (~100 LOC); can be moved into a tiny shared crate if it grows, but for v1 a cut-and-pasted module is fine.
- `serde_json` stays on the acceptor for the control channel; the per-conn child only sees raw TLS bytes — no JSON parsing.

Build + deploy:

- Repo: `colinrozzi/frontdoor`. PRs via auto-merge squash per [[feedback_mvp_velocity_auto_merge]].
- Release: nix-build → both wasm artifacts published as a GitHub release; sentinel pins the acceptor URL and the acceptor passes the conn URL into spawns.
- Sentinel renders the acceptor manifest with route-table initial state, and brings frontdoor-acceptor up as a managed sibling. Per-conn children are spawned by the acceptor, not sentinel — sentinel only sees the acceptor's chain.

## 10. Scope cuts (what we are NOT building in v0)

- No HTTP `:80` listener (no ACME challenge proxying, no HTTP-to-HTTPS redirect for the world).
- No TLS termination of any kind. (Lever held; explicitly v1+.)
- No wildcard SNI matching (`*.colinrozzi.com`).
- No active backend health checks.
- No internal retries on backend connect failures.
- No per-route rate limiting / per-IP rate limiting.
- No structured access logging beyond Theater's actor-level event log. (Hostname + backend_addr for each connection is plenty for v0.)
- No metrics emission. (Add a `theater:simple/metrics` integration in v1 once it exists.)

## 11. Open follow-ups (post-v1)

- **`splice(in, out)` host primitive** — bidirectional host-side byte pump, no wasm round-trips per chunk. Theater-dev estimates ~150 LOC in `theater-handler-tcp` + new function in `tcp.pact`. Bigger win under v1 (per-conn-child does the forwarding) than it would have been under v0 — each child still pays the host↔wasm crossing per chunk today. Ship v1 first, profile, add splice if crossings show up as the bottleneck.
- **Half-close primitive (`shutdown-write(conn)`)** — only if a routed protocol surfaces a need. Current API closes both directions, which is fine for TLS-encrypted streams.
- Wildcard SNI routes.
- Active backend health checks + fast-fail.
- `:80` listener for ACME HTTP-01 dispatching, possibly enabling centralized cert provisioning.
- TLS-termination mode for backends that don't want their own cert juggling.
- Per-connection rate limiting / abuse defense (route-table-side: cap concurrent children per source IP).
- Structured access logging — the acceptor records each spawn + exit; if we want headers / SNI / backend / bytes-transferred captured, the per-conn child needs an exit-time log emit. Simple add.

## 12. Risks

- **Spawn-rate ceiling.** Per-conn-child model spawns one wasm actor instance per accepted TCP connection. If accept rate is high (a scanner storm of 1000+ conn/sec), actor spawn becomes the hot path. Theater's actor spawn cost is ~ms order today (manifest fetch is cached after the first spawn; wasm instantiation is the dominant cost). Mitigation if it bites: cap accept rate at the acceptor (don't `accept` faster than a configured threshold), or batch-spawn pre-warmed children. Defer until measured under real traffic.
- **Cutover from `inbox-acceptor` owning `:443`.** The swap drops in-flight TLS connections at the moment inbox-acceptor unbinds. Mitigation: schedule during low-traffic window, coordinate with inbox-dev and sentinel-dev. Cutover proper is already gated on this redesign per manager id=38.
- **Adversarial ClientHellos** (intentionally fragmented, oversized, malformed) could DoS the SNI-parsing path on the per-conn child. The blast radius shrinks dramatically vs. v0 — only that child crashes, not the acceptor. Mitigation: bound buffer size + read-count, close on parse failure, log + exit (§3.a).
- **FD-handoff primitive doesn't exist yet (§6.c.ii).** v1 implementation blocked on a new theater host function — likely `hand-off-connection(conn-id, target-actor-id)` on `theater:simple/tcp`. This is the real gate, not the subscription API (which shipped 2026-06-08 in theater 0.3.25). Mitigation: nothing actionable until theater-dev / Colin land the primitive design; the design doc captures the dependency clearly so theater-side scoping has the constraint.

— end —
