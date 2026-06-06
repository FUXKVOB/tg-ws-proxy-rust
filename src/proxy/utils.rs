use std::collections::HashMap;

pub const ZERO_64: [u8; 64] = [0u8; 64];
pub const HANDSHAKE_LEN: usize = 64;
pub const SKIP_LEN: usize = 8;
pub const PREKEY_LEN: usize = 32;
pub const KEY_LEN: usize = 32;
pub const IV_LEN: usize = 16;
pub const PROTO_TAG_POS: usize = 56;
pub const DC_IDX_POS: usize = 60;

pub const PROTO_TAG_ABRIDGED: [u8; 4] = [0xef, 0xef, 0xef, 0xef];
pub const PROTO_TAG_INTERMEDIATE: [u8; 4] = [0xee, 0xee, 0xee, 0xee];
pub const PROTO_TAG_SECURE: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

pub const PROTO_ABRIDGED_INT: u32 = 0xEFEF_EFEF;
pub const PROTO_INTERMEDIATE_INT: u32 = 0xEEEE_EEEE;
pub const PROTO_PADDED_INTERMEDIATE_INT: u32 = 0xDDDD_DDDD;

pub const RESERVED_FIRST_BYTES: [u8; 1] = [0xEF];
pub const RESERVED_STARTS: [[u8; 4]; 6] = [
    [0x48, 0x45, 0x41, 0x44],
    [0x50, 0x4F, 0x53, 0x54],
    [0x47, 0x45, 0x54, 0x20],
    [0xee, 0xee, 0xee, 0xee],
    [0xdd, 0xdd, 0xdd, 0xdd],
    [0x16, 0x03, 0x01, 0x02],
];
pub const RESERVED_CONTINUE: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

pub fn dc_default_ips() -> HashMap<u32, &'static str> {
    HashMap::from([
        (1, "149.154.175.50"),
        (2, "149.154.167.51"),
        (3, "149.154.175.100"),
        (4, "149.154.167.91"),
        (5, "149.154.171.5"),
        (203, "91.105.192.100"),
    ])
}

pub fn ws_domains(dc: u32, is_media: bool) -> Vec<String> {
    let dc = if dc == 203 { 2 } else { dc };
    if is_media {
        vec![
            format!("kws{}-1.web.telegram.org", dc),
            format!("kws{}.web.telegram.org", dc),
        ]
    } else {
        vec![
            format!("kws{}.web.telegram.org", dc),
            format!("kws{}-1.web.telegram.org", dc),
        ]
    }
}

pub fn get_link_host(host: &str) -> Option<String> {
    if host == "0.0.0.0" {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        let local = socket.local_addr().ok()?;
        Some(local.ip().to_string())
    } else {
        Some(host.into())
    }
}
