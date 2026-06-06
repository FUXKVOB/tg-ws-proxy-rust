use aes::cipher::StreamCipher;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::proxy::crypto::*;
use crate::proxy::utils::*;

pub fn try_handshake(
    handshake: &[u8],
    secret: &[u8],
) -> Option<(u32, bool, [u8; 4], [u8; 48])> {
    if handshake.len() < HANDSHAKE_LEN {
        return None;
    }

    let dec_prekey_and_iv = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let dec_prekey = &dec_prekey_and_iv[..PREKEY_LEN];
    let dec_iv = &dec_prekey_and_iv[PREKEY_LEN..];

    let mut hasher = Sha256::new();
    hasher.update(dec_prekey);
    hasher.update(secret);
    let dec_key = hasher.finalize();

    let mut decryptor = aes_ctr_new(&dec_key, dec_iv);
    let mut decrypted = handshake.to_vec();
    decryptor.apply_keystream(&mut decrypted);

    let mut proto_tag = [0u8; 4];
    proto_tag.copy_from_slice(&decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4]);

    if proto_tag != PROTO_TAG_ABRIDGED
        && proto_tag != PROTO_TAG_INTERMEDIATE
        && proto_tag != PROTO_TAG_SECURE
    {
        return None;
    }

    let mut dc_idx_bytes = [0u8; 2];
    dc_idx_bytes.copy_from_slice(&decrypted[DC_IDX_POS..DC_IDX_POS + 2]);
    let dc_idx = i16::from_le_bytes(dc_idx_bytes);

    let dc_id = dc_idx.unsigned_abs() as u32;
    let is_media = dc_idx < 0;

    let mut result = [0u8; 48];
    result.copy_from_slice(dec_prekey_and_iv);
    Some((dc_id, is_media, proto_tag, result))
}

pub fn generate_relay_init(proto_tag: &[u8; 4], dc_idx: i16) -> Vec<u8> {
    loop {
        let mut rnd = [0u8; HANDSHAKE_LEN];
        rand::rng().fill_bytes(&mut rnd);

        if RESERVED_FIRST_BYTES.contains(&rnd[0]) {
            continue;
        }
        if RESERVED_STARTS.iter().any(|&s| rnd[..4] == s) {
            continue;
        }
        if rnd[4..8] == RESERVED_CONTINUE {
            continue;
        }

        let mut result = rnd.to_vec();

        let enc_key = &rnd[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
        let enc_iv = &rnd[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

        let mut encryptor = aes_ctr_new(enc_key, enc_iv);
        encryptor.apply_keystream(&mut result);

        let keystream_tail: Vec<u8> = result[56..64]
            .iter()
            .zip(&rnd[56..64])
            .map(|(a, b)| a ^ b)
            .collect();

        let dc_bytes = dc_idx.to_le_bytes();
        let mut tail_plain = proto_tag.to_vec();
        tail_plain.extend_from_slice(&dc_bytes);
        tail_plain.extend_from_slice(&[0u8, 0u8]);

        let encrypted_tail: Vec<u8> = tail_plain
            .iter()
            .zip(&keystream_tail)
            .map(|(a, b)| a ^ b)
            .collect();

        result[56..64].copy_from_slice(&encrypted_tail);
        return result;
    }
}

pub fn build_crypto_ctx(
    client_dec_prekey_iv: &[u8; 48],
    secret: &[u8],
    relay_init: &[u8],
) -> CryptoContext {
    let clt_dec_prekey = &client_dec_prekey_iv[..PREKEY_LEN];
    let clt_dec_iv = &client_dec_prekey_iv[PREKEY_LEN..];
    let clt_dec_key = {
        let mut h = Sha256::new();
        h.update(clt_dec_prekey);
        h.update(secret);
        h.finalize()
    };

    let mut clt_enc_prekey_iv = [0u8; 48];
    clt_enc_prekey_iv.copy_from_slice(client_dec_prekey_iv);
    clt_enc_prekey_iv.reverse();
    let clt_enc_key = {
        let mut h = Sha256::new();
        h.update(&clt_enc_prekey_iv[..PREKEY_LEN]);
        h.update(secret);
        h.finalize()
    };
    let clt_enc_iv = &clt_enc_prekey_iv[PREKEY_LEN..];

    let mut clt_dec = aes_ctr_new(&clt_dec_key, clt_dec_iv);
    let clt_enc = aes_ctr_new(&clt_enc_key, clt_enc_iv);
    clt_dec.apply_keystream(&mut ZERO_64.to_vec());

    let relay_enc_key = &relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let relay_enc_iv = &relay_init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

    let mut relay_dec_prekey_iv = [0u8; 48];
    relay_dec_prekey_iv.copy_from_slice(&relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]);
    relay_dec_prekey_iv.reverse();
    let relay_dec_key = relay_dec_prekey_iv[..KEY_LEN].to_vec();
    let relay_dec_iv = relay_dec_prekey_iv[KEY_LEN..].to_vec();

    let mut tg_enc = aes_ctr_new(relay_enc_key, relay_enc_iv);
    let tg_dec = aes_ctr_new(&relay_dec_key, &relay_dec_iv);
    tg_enc.apply_keystream(&mut ZERO_64.to_vec());

    CryptoContext {
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
    }
}

pub struct CryptoContext {
    pub clt_dec: AesCtr,
    pub clt_enc: AesCtr,
    pub tg_enc: AesCtr,
    pub tg_dec: AesCtr,
}

pub struct MsgSplitter {
    dec: AesCtr,
    proto: u32,
    cipher_buf: Vec<u8>,
    plain_buf: Vec<u8>,
    disabled: bool,
}

impl MsgSplitter {
    pub fn new(relay_init: &[u8], proto_int: u32) -> Self {
        let mut dec = aes_ctr_new(&relay_init[8..40], &relay_init[40..56]);
        dec.apply_keystream(&mut ZERO_64.to_vec());
        Self {
            dec,
            proto: proto_int,
            cipher_buf: Vec::new(),
            plain_buf: Vec::new(),
            disabled: false,
        }
    }

    pub fn split(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        if chunk.is_empty() {
            return vec![];
        }
        if self.disabled {
            return vec![chunk.to_vec()];
        }

        self.cipher_buf.extend_from_slice(chunk);
        let mut decrypted = chunk.to_vec();
        self.dec.apply_keystream(&mut decrypted);
        self.plain_buf.extend_from_slice(&decrypted);

        let mut parts = Vec::new();
        let mut offset = 0;
        let buf_len = self.cipher_buf.len();

        while offset < buf_len {
            let avail = buf_len - offset;
            match self.next_packet_len(offset, avail) {
                Some(packet_len) if packet_len > 0 && packet_len <= avail => {
                    parts.push(self.cipher_buf[offset..offset + packet_len].to_vec());
                    offset += packet_len;
                }
                Some(0) => {
                    parts.push(self.cipher_buf[offset..].to_vec());
                    offset = buf_len;
                    self.disabled = true;
                    break;
                }
                _ => break,
            }
        }

        if offset > 0 {
            self.cipher_buf.drain(..offset);
            self.plain_buf.drain(..offset);
        }
        parts
    }

    fn next_packet_len(&self, offset: usize, avail: usize) -> Option<usize> {
        if avail == 0 {
            return None;
        }
        match self.proto {
            PROTO_ABRIDGED_INT => self.next_abridged_len(offset, avail),
            PROTO_INTERMEDIATE_INT | PROTO_PADDED_INTERMEDIATE_INT => {
                self.next_intermediate_len(offset, avail)
            }
            _ => Some(0),
        }
    }

    fn next_abridged_len(&self, offset: usize, avail: usize) -> Option<usize> {
        let first = self.plain_buf[offset];
        if first == 0x7F || first == 0xFF {
            if avail < 4 {
                return None;
            }
            let payload = u32::from_le_bytes(
                self.plain_buf[offset + 1..offset + 4].try_into().unwrap(),
            ) as usize * 4;
            if payload == 0 {
                return Some(0);
            }
            Some(4 + payload)
        } else {
            let payload = (first as usize & 0x7F) * 4;
            if payload == 0 {
                return Some(0);
            }
            let packet_len = 1 + payload;
            if avail < packet_len {
                return None;
            }
            Some(packet_len)
        }
    }

    fn next_intermediate_len(&self, offset: usize, avail: usize) -> Option<usize> {
        if avail < 4 {
            return None;
        }
        let payload =
            u32::from_le_bytes(self.plain_buf[offset..offset + 4].try_into().unwrap()) as usize
                & 0x7FFF_FFFF;
        if payload == 0 {
            return Some(0);
        }
        let packet_len = 4 + payload;
        if avail < packet_len {
            return None;
        }
        Some(packet_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_relay_init_length() {
        let init = generate_relay_init(&PROTO_TAG_INTERMEDIATE, 2);
        assert_eq!(init.len(), HANDSHAKE_LEN);
    }
}
