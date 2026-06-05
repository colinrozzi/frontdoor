//! Hand-rolled TLS ClientHello SNI parser.
//!
//! Walks the TLS record + Handshake headers + ClientHello body to find
//! the `server_name` extension (extension type `0x0000`), then returns
//! the first hostname-typed entry inside it. No crypto, no rustls
//! dependency, no parser combinator framework.
//!
//! See RFC 8446 §4.1.2 (ClientHello) and RFC 6066 §3 (server_name
//! extension).

use alloc::string::{String, ToString};

pub enum SniResult {
    /// SNI extracted successfully.
    Found(String),
    /// Need more bytes — the buffer is a strict prefix of the
    /// ClientHello.
    Incomplete,
    /// ClientHello was complete but contained no SNI extension. The
    /// caller decides whether to drop or fall back to a default
    /// backend.
    Absent,
    /// Bytes are not a parseable TLS ClientHello.
    Malformed(&'static str),
}

const RECORD_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const EXTENSION_SERVER_NAME: u16 = 0x0000;
const NAME_TYPE_HOST_NAME: u8 = 0x00;

pub fn parse_sni(buf: &[u8]) -> SniResult {
    let mut p = Parser::new(buf);

    // ───── TLS record header (5 bytes) ─────
    let record_type = match p.u8() {
        Some(b) => b,
        None => return SniResult::Incomplete,
    };
    if record_type != RECORD_TYPE_HANDSHAKE {
        return SniResult::Malformed("first byte is not a handshake record");
    }
    if p.skip(2).is_err() {
        return SniResult::Incomplete; // legacy version
    }
    let record_len = match p.u16() {
        Some(n) => n as usize,
        None => return SniResult::Incomplete,
    };
    if buf.len() < 5 + record_len {
        return SniResult::Incomplete;
    }

    // Restrict the parser to the record payload from here on — anything
    // past the record-length is a separate record we ignore.
    let mut p = Parser::new(&buf[5..5 + record_len]);

    // ───── Handshake header (4 bytes) ─────
    match p.u8() {
        Some(HANDSHAKE_TYPE_CLIENT_HELLO) => {}
        Some(_) => return SniResult::Malformed("not a ClientHello"),
        None => return SniResult::Incomplete,
    }
    let hs_len = match p.u24() {
        Some(n) => n as usize,
        None => return SniResult::Incomplete,
    };
    if p.remaining() < hs_len {
        return SniResult::Incomplete;
    }
    let mut p = Parser::new(&p.tail()[..hs_len]);

    // ───── ClientHello body ─────
    if p.skip(2).is_err() {
        // client_version
        return SniResult::Incomplete;
    }
    if p.skip(32).is_err() {
        // random
        return SniResult::Incomplete;
    }
    let sid_len = match p.u8() {
        Some(n) => n as usize,
        None => return SniResult::Incomplete,
    };
    if p.skip(sid_len).is_err() {
        return SniResult::Incomplete;
    }
    let cs_len = match p.u16() {
        Some(n) => n as usize,
        None => return SniResult::Incomplete,
    };
    if p.skip(cs_len).is_err() {
        return SniResult::Incomplete;
    }
    let cm_len = match p.u8() {
        Some(n) => n as usize,
        None => return SniResult::Incomplete,
    };
    if p.skip(cm_len).is_err() {
        return SniResult::Incomplete;
    }
    // TLS 1.2 omits extensions when none are sent. If we hit EOF here
    // the ClientHello is well-formed but has no extensions block; SNI
    // is therefore absent.
    let ext_total = match p.u16() {
        Some(n) => n as usize,
        None => return SniResult::Absent,
    };
    if p.remaining() < ext_total {
        return SniResult::Incomplete;
    }

    let mut ep = Parser::new(&p.tail()[..ext_total]);
    while ep.remaining() >= 4 {
        let ext_type = ep.u16().unwrap();
        let ext_len = ep.u16().unwrap() as usize;
        if ep.remaining() < ext_len {
            return SniResult::Malformed("extension overflows extensions block");
        }
        let ext_body = &ep.tail()[..ext_len];
        let _ = ep.skip(ext_len);
        if ext_type == EXTENSION_SERVER_NAME {
            return parse_server_name(ext_body);
        }
    }
    SniResult::Absent
}

/// RFC 6066 §3:
///   ServerNameList: u16 length + list of ServerName
///   ServerName:     u8 name_type + opaque host_name<1..2^16-1>
fn parse_server_name(buf: &[u8]) -> SniResult {
    let mut p = Parser::new(buf);
    let list_len = match p.u16() {
        Some(n) => n as usize,
        None => return SniResult::Malformed("server_name: short list length"),
    };
    if p.remaining() < list_len {
        return SniResult::Malformed("server_name: short list payload");
    }
    let mut lp = Parser::new(&p.tail()[..list_len]);
    while lp.remaining() >= 3 {
        let name_type = lp.u8().unwrap();
        let name_len = lp.u16().unwrap() as usize;
        if lp.remaining() < name_len {
            return SniResult::Malformed("server_name: name overflows");
        }
        let body = &lp.tail()[..name_len];
        let _ = lp.skip(name_len);
        if name_type == NAME_TYPE_HOST_NAME {
            return match core::str::from_utf8(body) {
                Ok(s) => SniResult::Found(s.to_string()),
                Err(_) => SniResult::Malformed("server_name: non-utf8 hostname"),
            };
        }
    }
    SniResult::Absent
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn tail(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        if self.remaining() < 2 {
            return None;
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }
    fn u24(&mut self) -> Option<u32> {
        if self.remaining() < 3 {
            return None;
        }
        let v = ((self.buf[self.pos] as u32) << 16)
            | ((self.buf[self.pos + 1] as u32) << 8)
            | (self.buf[self.pos + 2] as u32);
        self.pos += 3;
        Some(v)
    }
    fn skip(&mut self, n: usize) -> Result<(), ()> {
        if self.remaining() < n {
            return Err(());
        }
        self.pos += n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Build a minimal but spec-compliant ClientHello with the given SNI.
    fn make_client_hello_with_sni(sni: &str) -> Vec<u8> {
        // server_name extension body: list_len(2) | name_type(1) | name_len(2) | name
        let mut sn_body: Vec<u8> = Vec::new();
        sn_body.extend_from_slice(&((3 + sni.len()) as u16).to_be_bytes()); // list length
        sn_body.push(NAME_TYPE_HOST_NAME);
        sn_body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sn_body.extend_from_slice(sni.as_bytes());

        // extensions block: ext_type(2) | ext_len(2) | body
        let mut ext_block: Vec<u8> = Vec::new();
        ext_block.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
        ext_block.extend_from_slice(&(sn_body.len() as u16).to_be_bytes());
        ext_block.extend_from_slice(&sn_body);

        // ClientHello body:
        //   client_version(2) | random(32) | sid_len(1)=0 | cs_len(2)=2 | cs(2) | cm_len(1)=1 | cm(1)=0 | ext_total(2) | ext_block
        let mut ch_body: Vec<u8> = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        ch_body.extend_from_slice(&[0u8; 32]); // random
        ch_body.push(0); // session_id length
        ch_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // 1 cipher_suite (TLS_AES_128_GCM_SHA256)
        ch_body.extend_from_slice(&[0x01, 0x00]); // 1 compression_method (null)
        ch_body.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&ext_block);

        // Handshake header: type(1)=ClientHello | length(3)
        let mut hs: Vec<u8> = Vec::new();
        hs.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        hs.push(0);
        hs.extend_from_slice(&(ch_body.len() as u16).to_be_bytes());
        hs.extend_from_slice(&ch_body);

        // Record header: type(1)=Handshake | version(2) | length(2)
        let mut record: Vec<u8> = Vec::new();
        record.push(RECORD_TYPE_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]); // legacy version
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn extracts_sni_from_well_formed_clienthello() {
        let buf = make_client_hello_with_sni("mail.colinrozzi.com");
        match parse_sni(&buf) {
            SniResult::Found(s) => assert_eq!(s, "mail.colinrozzi.com"),
            other => panic!("expected Found, got {:?}", match other {
                SniResult::Incomplete => "Incomplete",
                SniResult::Absent => "Absent",
                SniResult::Malformed(m) => m,
                SniResult::Found(_) => unreachable!(),
            }),
        }
    }

    #[test]
    fn incomplete_when_partial() {
        let buf = make_client_hello_with_sni("mail.colinrozzi.com");
        for n in 0..buf.len() {
            match parse_sni(&buf[..n]) {
                SniResult::Incomplete => {}
                SniResult::Found(_) => panic!("found SNI on prefix of length {}", n),
                SniResult::Absent => panic!("Absent on prefix of length {}", n),
                SniResult::Malformed(m) => panic!(
                    "Malformed on prefix of length {}: {}",
                    n, m
                ),
            }
        }
    }

    #[test]
    fn malformed_when_first_byte_wrong() {
        let buf = vec![0x17u8, 0x03, 0x03, 0x00, 0x10];
        match parse_sni(&buf) {
            SniResult::Malformed(_) => {}
            _ => panic!("expected Malformed"),
        }
    }
}
