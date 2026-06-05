//! frontdoor — Theater-native SNI-routing front door for colinrozzi.com.
//!
//! Singleton actor that:
//!   * Binds `0.0.0.0:443` (public TLS) and `127.0.0.1:9100` (control).
//!   * Accepts every inbound TCP connection in active mode and classifies
//!     it by first byte:  `0x16` → TLS ClientHello, `0x7B` (`{`) → control
//!     JSON command. Anything else → close.
//!   * For TLS, walks the ClientHello to extract the SNI hostname, looks
//!     it up in the routing table, opens an outbound TCP connection to
//!     the backend, replays the buffered ClientHello bytes, and bridges
//!     the two connections both ways via active-mode `on-data` callbacks.
//!   * For control, reads newline-delimited JSON commands
//!     (`upsert_route`, `delete_route`, `set_default`, `list_routes`)
//!     and mutates the in-memory routing table.
//!
//! Frontdoor NEVER terminates TLS — every byte after the SNI peek is
//! forwarded raw to the backend. See `DESIGN.md` §1–§6 for the full
//! architectural rationale.

#![cfg_attr(not(test), no_std)]
extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use packr_guest::{export, import, pack_types, GraphValue, Value};
use serde::Deserialize;

#[cfg(not(test))]
packr_guest::setup_guest!();

mod sni;

const DEFAULT_PUBLIC_LISTEN_ADDR: &str = "0.0.0.0:443";
const DEFAULT_CONTROL_LISTEN_ADDR: &str = "127.0.0.1:9100";

/// Cap on bytes buffered while waiting for either the ClientHello or a
/// newline-terminated control command. Adversarial inputs that exceed
/// this are dropped.
const PENDING_BUFFER_CAP: usize = 8 * 1024;

// ───────────────────────────── state ─────────────────────────────────

#[derive(Clone, GraphValue)]
#[graph(crate = "packr_guest::composite_abi")]
pub struct Route {
    pub hostname: String,
    pub backend: String,
}

/// `kind`:
///   * `"unknown"` — no bytes seen yet; classify on first chunk
///   * `"tls"`     — accumulating ClientHello bytes
///   * `"control"` — accumulating newline-delimited JSON
#[derive(Clone, GraphValue)]
#[graph(crate = "packr_guest::composite_abi")]
pub struct Pending {
    pub conn_id: String,
    pub kind: String,
    pub buf: Vec<u8>,
}

#[derive(Clone, GraphValue)]
#[graph(crate = "packr_guest::composite_abi")]
pub struct Pipe {
    pub a: String,
    pub b: String,
}

#[derive(Clone, GraphValue)]
#[graph(crate = "packr_guest::composite_abi")]
pub struct FrontdoorState {
    pub public_listener_id: String,
    pub control_listener_id: String,
    pub routes: Vec<Route>,
    pub default_backend: String, // empty = no default
    pub pending: Vec<Pending>,
    pub pipes: Vec<Pipe>,
}

// ─────────────────────────── ABI surface ─────────────────────────────

pack_types! {
    imports {
        theater:simple/runtime {
            log: func(msg: string),
        }
        theater:simple/tcp {
            listen: func(address: string) -> result<string, string>,
            connect: func(address: string) -> result<string, string>,
            activate: func(connection-id: string) -> result<_, string>,
            set-active: func(connection-id: string, mode: string) -> result<_, string>,
            send: func(connection-id: string, data: list<u8>) -> result<u64, string>,
            close: func(connection-id: string) -> result<_, string>,
        }
    }
    exports {
        theater:simple/actor.init: func(state: value) -> result<frontdoor-state, string>,
        theater:simple/tcp-client.handle-connection: func(state: frontdoor-state, connection-id: string) -> result<frontdoor-state, string>,
        theater:simple/tcp-client.on-data: func(state: frontdoor-state, connection-id: string, data: list<u8>) -> result<frontdoor-state, string>,
        theater:simple/tcp-client.on-close: func(state: frontdoor-state, connection-id: string, reason: string) -> result<frontdoor-state, string>,
    }
}

#[import(module = "theater:simple/runtime", name = "log")]
fn log(msg: String);

#[import(module = "theater:simple/tcp", name = "listen")]
fn tcp_listen(address: String) -> Result<String, String>;

#[import(module = "theater:simple/tcp", name = "connect")]
fn tcp_connect(address: String) -> Result<String, String>;

#[import(module = "theater:simple/tcp", name = "activate")]
fn tcp_activate(conn_id: String) -> Result<(), String>;

#[import(module = "theater:simple/tcp", name = "set-active")]
fn tcp_set_active(conn_id: String, mode: String) -> Result<(), String>;

#[import(module = "theater:simple/tcp", name = "send")]
fn tcp_send(conn_id: String, data: Vec<u8>) -> Result<u64, String>;

#[import(module = "theater:simple/tcp", name = "close")]
fn tcp_close(conn_id: String) -> Result<(), String>;

// ─────────────────────── initial-state schema ────────────────────────

#[derive(Deserialize)]
struct InitConfig {
    #[serde(default)]
    default_backend: Option<String>,
    #[serde(default)]
    routes: Vec<InitRoute>,
    /// Override the public listen address. Defaults to `0.0.0.0:443`.
    /// Useful for local smoke tests on a high port.
    #[serde(default)]
    public_listen_addr: Option<String>,
    /// Override the control listen address. Defaults to
    /// `127.0.0.1:9100`. Bound on a different loopback port for
    /// concurrent test runs.
    #[serde(default)]
    control_listen_addr: Option<String>,
}

#[derive(Deserialize)]
struct InitRoute {
    hostname: String,
    backend: String,
}

// ─────────────────────────── lifecycle ───────────────────────────────

#[export(name = "theater:simple/actor.init")]
fn init(state: Value) -> Result<(FrontdoorState, ()), String> {
    log(String::from("[frontdoor] init"));

    let (routes, default_backend, public_addr, control_addr) = match state {
        Value::String(s) if !s.is_empty() => {
            let cfg: InitConfig = serde_json::from_str(&s)
                .map_err(|e| format!("initial_state must be JSON: {}", e))?;
            let routes = cfg
                .routes
                .into_iter()
                .map(|r| Route {
                    hostname: r.hostname,
                    backend: r.backend,
                })
                .collect::<Vec<_>>();
            (
                routes,
                cfg.default_backend.unwrap_or_default(),
                cfg.public_listen_addr
                    .unwrap_or_else(|| String::from(DEFAULT_PUBLIC_LISTEN_ADDR)),
                cfg.control_listen_addr
                    .unwrap_or_else(|| String::from(DEFAULT_CONTROL_LISTEN_ADDR)),
            )
        }
        _ => (
            Vec::new(),
            String::new(),
            String::from(DEFAULT_PUBLIC_LISTEN_ADDR),
            String::from(DEFAULT_CONTROL_LISTEN_ADDR),
        ),
    };

    let public_listener_id = tcp_listen(public_addr.clone())
        .map_err(|e| format!("listen public {}: {}", public_addr, e))?;
    let control_listener_id = tcp_listen(control_addr.clone())
        .map_err(|e| format!("listen control {}: {}", control_addr, e))?;

    log(format!(
        "[frontdoor] public={} control={} routes={} default={}",
        public_addr,
        control_addr,
        routes.len(),
        if default_backend.is_empty() {
            "<none>"
        } else {
            default_backend.as_str()
        }
    ));

    Ok((
        FrontdoorState {
            public_listener_id,
            control_listener_id,
            routes,
            default_backend,
            pending: Vec::new(),
            pipes: Vec::new(),
        },
        (),
    ))
}

#[export(name = "theater:simple/tcp-client.handle-connection")]
fn handle_connection(
    state: FrontdoorState,
    conn_id: String,
) -> Result<(FrontdoorState, ()), String> {
    let mut state = state;
    // Single failing accept must never kill the listener. Log + drop the
    // pending connection record + carry on. Mirrors the inbox-acceptor
    // discipline: a per-connection error must not propagate up the
    // supervision tree.
    if let Err(e) = activate_and_arm(&conn_id) {
        log(format!(
            "[frontdoor] handle-connection {} activate failed: {}",
            conn_id, e
        ));
        let _ = tcp_close(conn_id.clone());
        return Ok((state, ()));
    }
    state.pending.push(Pending {
        conn_id,
        kind: String::from("unknown"),
        buf: Vec::new(),
    });
    Ok((state, ()))
}

fn activate_and_arm(conn_id: &str) -> Result<(), String> {
    tcp_activate(conn_id.to_string())?;
    tcp_set_active(conn_id.to_string(), String::from("active"))?;
    Ok(())
}

#[export(name = "theater:simple/tcp-client.on-data")]
fn on_data(
    state: FrontdoorState,
    conn_id: String,
    data: Vec<u8>,
) -> Result<(FrontdoorState, ()), String> {
    let mut state = state;
    if let Some(idx) = find_pending(&state.pending, &conn_id) {
        handle_pending_data(&mut state, idx, data);
    } else if let Some(peer) = find_peer(&state.pipes, &conn_id) {
        // Mid-stream byte; forward to peer. EOF from the kernel is
        // delivered via on-close, not an empty on-data, so any payload
        // here is real bytes.
        if let Err(e) = tcp_send(peer.clone(), data) {
            log(format!(
                "[frontdoor] forward send {} -> {} failed: {}; tearing down pipe",
                conn_id, peer, e
            ));
            close_pipe(&mut state, &conn_id);
        }
    } else {
        // No state for this conn. Possible races: control conn closed
        // mid-handler, or stray callback after close. Drop quietly.
        log(format!(
            "[frontdoor] on-data {} bytes={} but no state; closing",
            conn_id,
            data.len()
        ));
        let _ = tcp_close(conn_id);
    }
    Ok((state, ()))
}

#[export(name = "theater:simple/tcp-client.on-close")]
fn on_close(
    state: FrontdoorState,
    conn_id: String,
    reason: String,
) -> Result<(FrontdoorState, ()), String> {
    let mut state = state;
    log(format!("[frontdoor] on-close {} reason={}", conn_id, reason));

    // Pending connection: drop the buffer + close the (possibly already
    // half-closed) socket. No outbound yet, so nothing else to tear down.
    if let Some(idx) = find_pending(&state.pending, &conn_id) {
        state.pending.swap_remove(idx);
        let _ = tcp_close(conn_id);
        return Ok((state, ()));
    }

    // Steady-state pipe: close the peer, drop both pipe entries. The
    // already-closed side gets a redundant close() — harmless.
    if find_peer(&state.pipes, &conn_id).is_some() {
        close_pipe(&mut state, &conn_id);
        return Ok((state, ()));
    }

    // Unknown conn (likely already cleaned up). Make the close idempotent.
    let _ = tcp_close(conn_id);
    Ok((state, ()))
}

// ───────────────────── connection state machine ──────────────────────

/// Handle a chunk of bytes arriving on a connection that is still in
/// the pending (pre-classification or mid-buffer) state.
fn handle_pending_data(state: &mut FrontdoorState, idx: usize, data: Vec<u8>) {
    // Borrow the pending entry, mutate its buffer + kind. We don't move
    // it out of the Vec until the connection is either fully classified
    // (TLS path: promoted to pipes) or torn down.
    let conn_id;
    let new_buf;
    let kind;
    {
        let p = &mut state.pending[idx];
        if p.kind == "unknown" {
            if let Some(b) = data.first() {
                p.kind = classify(*b).to_string();
            }
        }
        p.buf.extend_from_slice(&data);
        if p.buf.len() > PENDING_BUFFER_CAP {
            log(format!(
                "[frontdoor] {} exceeded pending buffer cap ({} bytes); closing",
                p.conn_id, PENDING_BUFFER_CAP
            ));
            conn_id = p.conn_id.clone();
            state.pending.swap_remove(idx);
            let _ = tcp_close(conn_id);
            return;
        }
        conn_id = p.conn_id.clone();
        kind = p.kind.clone();
        new_buf = p.buf.clone();
    }

    match kind.as_str() {
        "tls" => handle_tls_pending(state, idx, conn_id, new_buf),
        "control" => handle_control_pending(state, idx, conn_id, new_buf),
        _ => {
            log(format!(
                "[frontdoor] {} unclassifiable first byte; closing",
                conn_id
            ));
            state.pending.swap_remove(idx);
            let _ = tcp_close(conn_id);
        }
    }
}

fn classify(first_byte: u8) -> &'static str {
    match first_byte {
        0x16 => "tls",  // TLS ContentType.Handshake — start of a ClientHello record
        b'{' => "control",
        _ => "junk",
    }
}

fn handle_tls_pending(
    state: &mut FrontdoorState,
    idx: usize,
    conn_id: String,
    buf: Vec<u8>,
) {
    match sni::parse_sni(&buf) {
        sni::SniResult::Incomplete => {
            // Wait for more bytes. The pending entry is already updated.
        }
        sni::SniResult::Found(hostname) => {
            let backend = lookup_backend(state, &hostname);
            let backend = match backend {
                Some(b) => b,
                None => {
                    log(format!(
                        "[frontdoor] {} sni={} → no route; closing",
                        conn_id, hostname
                    ));
                    state.pending.swap_remove(idx);
                    let _ = tcp_close(conn_id);
                    return;
                }
            };
            promote_to_pipe(state, idx, conn_id, hostname, backend, buf);
        }
        sni::SniResult::Absent => {
            // Spec-valid ClientHello without SNI. Use default_backend or
            // drop.
            if state.default_backend.is_empty() {
                log(format!(
                    "[frontdoor] {} no SNI + no default_backend; closing",
                    conn_id
                ));
                state.pending.swap_remove(idx);
                let _ = tcp_close(conn_id);
                return;
            }
            let backend = state.default_backend.clone();
            promote_to_pipe(state, idx, conn_id, String::from("<no-sni>"), backend, buf);
        }
        sni::SniResult::Malformed(reason) => {
            log(format!(
                "[frontdoor] {} clienthello parse failed: {}; closing",
                conn_id, reason
            ));
            state.pending.swap_remove(idx);
            let _ = tcp_close(conn_id);
        }
    }
}

fn promote_to_pipe(
    state: &mut FrontdoorState,
    idx: usize,
    inbound: String,
    sni_label: String,
    backend: String,
    replay: Vec<u8>,
) {
    let outbound = match tcp_connect(backend.clone()) {
        Ok(c) => c,
        Err(e) => {
            log(format!(
                "[frontdoor] {} → connect({}) failed: {}; dropping client",
                inbound, backend, e
            ));
            state.pending.swap_remove(idx);
            let _ = tcp_close(inbound);
            return;
        }
    };

    // connect() returns a fully-active passive connection. Flip it to
    // active so on-data callbacks deliver backend → client bytes.
    if let Err(e) = tcp_set_active(outbound.clone(), String::from("active")) {
        log(format!(
            "[frontdoor] {} -> {} set-active failed: {}",
            inbound, outbound, e
        ));
        state.pending.swap_remove(idx);
        let _ = tcp_close(inbound);
        let _ = tcp_close(outbound);
        return;
    }

    // Replay the buffered ClientHello so the backend sees a normal TLS
    // stream from byte zero.
    if let Err(e) = tcp_send(outbound.clone(), replay) {
        log(format!(
            "[frontdoor] {} -> {} replay send failed: {}",
            inbound, outbound, e
        ));
        state.pending.swap_remove(idx);
        let _ = tcp_close(inbound);
        let _ = tcp_close(outbound);
        return;
    }

    state.pending.swap_remove(idx);
    state.pipes.push(Pipe {
        a: inbound.clone(),
        b: outbound.clone(),
    });
    log(format!(
        "[frontdoor] piped {} sni={} -> {} backend={}",
        inbound, sni_label, outbound, backend
    ));
}

fn handle_control_pending(
    state: &mut FrontdoorState,
    idx: usize,
    conn_id: String,
    buf: Vec<u8>,
) {
    // Consume every complete line in the buffer. Leftover (partial line)
    // stays in the pending entry until the next on-data fires.
    let mut consumed = 0usize;
    let mut responses: Vec<Vec<u8>> = Vec::new();
    while let Some(nl) = memchr_nl(&buf[consumed..]) {
        let line_end = consumed + nl;
        let line = &buf[consumed..line_end];
        consumed = line_end + 1;
        let response = control_dispatch(state, line);
        responses.push(response);
    }

    // Stash any unconsumed tail back into the pending entry, and clear
    // the kind so the next chunk doesn't re-classify.
    {
        let p = &mut state.pending[idx];
        p.buf = buf[consumed..].to_vec();
    }

    for r in responses {
        let _ = tcp_send(conn_id.clone(), r);
    }
}

fn memchr_nl(buf: &[u8]) -> Option<usize> {
    buf.iter().position(|b| *b == b'\n')
}

/// Newline-delimited JSON command dispatch.
fn control_dispatch(state: &mut FrontdoorState, line: &[u8]) -> Vec<u8> {
    let text = match core::str::from_utf8(line) {
        Ok(s) => s.trim(),
        Err(_) => return error_response("invalid utf-8"),
    };
    if text.is_empty() {
        return error_response("empty line");
    }
    #[derive(Deserialize)]
    struct Cmd {
        op: String,
        #[serde(default)]
        hostname: Option<String>,
        #[serde(default)]
        backend: Option<String>,
    }
    let cmd: Cmd = match serde_json::from_str(text) {
        Ok(c) => c,
        Err(e) => return error_response(&format!("parse: {}", e)),
    };
    match cmd.op.as_str() {
        "upsert_route" => {
            let h = match cmd.hostname {
                Some(s) if !s.is_empty() => s,
                _ => return error_response("upsert_route requires hostname"),
            };
            let b = match cmd.backend {
                Some(s) if !s.is_empty() => s,
                _ => return error_response("upsert_route requires backend"),
            };
            if let Some(existing) = state.routes.iter_mut().find(|r| r.hostname == h) {
                existing.backend = b;
            } else {
                state.routes.push(Route { hostname: h, backend: b });
            }
            ok_response()
        }
        "delete_route" => {
            let h = match cmd.hostname {
                Some(s) if !s.is_empty() => s,
                _ => return error_response("delete_route requires hostname"),
            };
            state.routes.retain(|r| r.hostname != h);
            ok_response()
        }
        "set_default" => {
            state.default_backend = cmd.backend.unwrap_or_default();
            ok_response()
        }
        "list_routes" => {
            let mut out = String::from("{\"ok\":true,\"routes\":[");
            for (i, r) in state.routes.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&format!(
                    "{{\"hostname\":{},\"backend\":{}}}",
                    json_str(&r.hostname),
                    json_str(&r.backend)
                ));
            }
            out.push_str("],\"default_backend\":");
            if state.default_backend.is_empty() {
                out.push_str("null");
            } else {
                out.push_str(&json_str(&state.default_backend));
            }
            out.push_str("}\n");
            out.into_bytes()
        }
        other => error_response(&format!("unknown op: {}", other)),
    }
}

fn ok_response() -> Vec<u8> {
    b"{\"ok\":true}\n".to_vec()
}

fn error_response(msg: &str) -> Vec<u8> {
    format!("{{\"ok\":false,\"error\":{}}}\n", json_str(msg)).into_bytes()
}

/// Minimal JSON string escape — covers the subset we emit (no high
/// codepoints, no surrogates).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ────────────────────────── lookups + cleanup ────────────────────────

fn find_pending(pending: &[Pending], conn_id: &str) -> Option<usize> {
    pending.iter().position(|p| p.conn_id == conn_id)
}

fn find_peer(pipes: &[Pipe], conn_id: &str) -> Option<String> {
    for p in pipes {
        if p.a == conn_id {
            return Some(p.b.clone());
        }
        if p.b == conn_id {
            return Some(p.a.clone());
        }
    }
    None
}

/// Close the connection AND its peer, removing the pipe entry. Both
/// `close` calls are best-effort: one side typically already closed,
/// so its `close()` returns an error that we ignore.
fn close_pipe(state: &mut FrontdoorState, conn_id: &str) {
    let peer = find_peer(&state.pipes, conn_id);
    state.pipes.retain(|p| p.a != conn_id && p.b != conn_id);
    let _ = tcp_close(conn_id.to_string());
    if let Some(p) = peer {
        let _ = tcp_close(p);
    }
}

fn lookup_backend(state: &FrontdoorState, hostname: &str) -> Option<String> {
    if let Some(r) = state.routes.iter().find(|r| r.hostname == hostname) {
        return Some(r.backend.clone());
    }
    if !state.default_backend.is_empty() {
        return Some(state.default_backend.clone());
    }
    None
}
