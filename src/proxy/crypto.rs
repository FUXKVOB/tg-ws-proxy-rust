use aes::cipher::KeyIvInit;
use aes::Aes256;
use ctr::Ctr128BE;

pub type AesCtr = Ctr128BE<Aes256>;

pub fn aes_ctr_new(key: &[u8], iv: &[u8]) -> AesCtr {
    AesCtr::new_from_slices(key, iv).expect("Invalid AES key/IV length")
}

pub fn xor_mask(data: &[u8], mask: &[u8; 4]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ mask[i & 3])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::StreamCipher;

    #[test]
    fn test_xor_mask() {
        let data = b"hello";
        let mask = b"\x01\x02\x03\x04";
        let masked = xor_mask(data, mask);
        let unmasked = xor_mask(&masked, mask);
        assert_eq!(&unmasked, data);
    }

    #[test]
    fn test_aes_ctr() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let mut cipher = aes_ctr_new(&key, &iv);
        let plaintext = b"test data 16 bytes";
        let mut buf = plaintext.to_vec();
        cipher.apply_keystream(&mut buf);
        assert_ne!(&buf, plaintext);

        let mut decipher = aes_ctr_new(&key, &iv);
        decipher.apply_keystream(&mut buf);
        assert_eq!(&buf, plaintext);
    }
}
