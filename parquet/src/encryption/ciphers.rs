// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! Encryption implementation specific to Parquet, as described
//! in the [spec](https://github.com/apache/parquet-format/blob/master/Encryption.md).

use crate::encryption::GCM_NONCE_LENGTH;
use aes_gcm::aead::consts::U12;
use aes_gcm::aes::Aes128;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, AesGcm, Key, Nonce,
};
use rand::prelude::*;
use ring::aead::{Aad, LessSafeKey, NonceSequence, UnboundKey, AES_128_GCM};
use ring::rand::{SecureRandom, SystemRandom};

pub trait BlockEncryptor {
    fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8>;
}

pub trait BlockDecryptor {
    fn decrypt(&self, length_and_ciphertext: &[u8], aad: &[u8]) -> Vec<u8>;
}

pub(crate) struct AesGcmGcmBlockEncryptor {
    rng: ThreadRng,
    cipher: AesGcm<Aes128, U12>, // todo support other key sizes
}

impl AesGcmGcmBlockEncryptor {
    pub(crate) fn new(key_bytes: &[u8]) -> Self {
        let key_size = key_bytes.len(); //todo check len
        let key_vec = Vec::from(key_bytes);
        let key = Key::<Aes128Gcm>::from_slice(&key_vec[..]);

        Self {
            rng: rand::thread_rng(),
            cipher: Aes128Gcm::new(&key),
        }
    }
}

impl BlockEncryptor for AesGcmGcmBlockEncryptor {
    fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let nonce_buf: [u8; GCM_NONCE_LENGTH] = self.rng.gen();
        let nonce = Nonce::from_slice(&nonce_buf[..]);

        let plaint_text = Payload {
            msg: &plaintext[..],
            aad: &aad[..],
        };

        match self.cipher.encrypt(&nonce, plaint_text) {
            Ok(encrypted) => {
                let len: [u8; 4] = [0; 4];
                // todo fill len
                let ctext = [&nonce_buf, &*encrypted].concat();
                [&len, &*ctext].concat()
            }
            Err(e) => panic!("Failed to encrypt {}", e),
        }
    }
}

pub(crate) struct GcmBlockDecryptor {
    cipher: AesGcm<Aes128, U12>, // todo support other key sizes
}

impl GcmBlockDecryptor {
    pub(crate) fn new(key_bytes: &[u8]) -> Self {
        let key_size = key_bytes.len(); //todo check key len
        let key_vec = Vec::from(key_bytes);
        let key = Key::<Aes128Gcm>::from_slice(&key_vec[..]);

        Self {
            cipher: Aes128Gcm::new(&key),
        }
    }
}

impl BlockDecryptor for GcmBlockDecryptor {
    fn decrypt(&self, length_and_ciphertext: &[u8], aad: &[u8]) -> Vec<u8> {
        let nonce = Nonce::from_slice(&length_and_ciphertext[4..16]);

        let cipher_text = Payload {
            msg: &length_and_ciphertext[16..],
            aad: &aad[..],
        };

        match self.cipher.decrypt(&nonce, cipher_text) {
            Ok(decrypted) => decrypted,
            Err(e) => panic!("{}", e),
        }
    }
}

const LEFT_FOUR: u128 = 0xffff_ffff_0000_0000_0000_0000_0000_0000;
const RIGHT_TWELVE: u128 = 0x0000_0000_ffff_ffff_ffff_ffff_ffff_ffff;
const NONCE_LEN: usize = 12;

struct CounterNonce {
    start: u128,
    counter: u128,
}

impl CounterNonce {
    pub fn new(rng: &SystemRandom) -> Self {
        let mut buf = [0; 16];
        rng.fill(&mut buf).unwrap();

        // Since this is a random seed value, endianess doesn't matter at all,
        // and we can use whatever is platform-native.
        let start = u128::from_ne_bytes(buf) & RIGHT_TWELVE;
        let counter = start.wrapping_add(1);

        Self { start, counter }
    }

    /// One accessor for the nonce bytes to avoid potentially flipping endianess
    #[inline]
    pub fn get_bytes(&self) -> [u8; NONCE_LEN] {
        self.counter.to_le_bytes()[0..NONCE_LEN].try_into().unwrap()
    }
}

impl NonceSequence for CounterNonce {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        // If we've wrapped around, we've exhausted this nonce sequence
        if (self.counter & RIGHT_TWELVE) == (self.start & RIGHT_TWELVE) {
            Err(ring::error::Unspecified)
        } else {
            // Otherwise, just advance and return the new value
            let buf: [u8; NONCE_LEN] = self.get_bytes();
            self.counter = self.counter.wrapping_add(1);
            Ok(ring::aead::Nonce::assume_unique_for_key(buf))
        }
    }
}

pub(crate) struct RingGcmBlockEncryptor {
    key: LessSafeKey,
    nonce_sequence: CounterNonce,
}

impl RingGcmBlockEncryptor {
    /// Create a new `RingGcmBlockEncryptor` with a random key and random nonce.
    /// The nonce will advance appropriately with each block encryption and
    /// return an error if it wraps around.
    pub(crate) fn new() -> Self {
        let rng = SystemRandom::new();
        let mut key_bytes = [0; 16];
        rng.fill(&mut key_bytes).unwrap();

        let key = UnboundKey::new(&AES_128_GCM, key_bytes.as_ref()).unwrap();
        let nonce = CounterNonce::new(&rng);

        Self {
            key: LessSafeKey::new(key),
            nonce_sequence: nonce,
        }
    }
}

impl BlockEncryptor for RingGcmBlockEncryptor {
    fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let nonce = self.nonce_sequence.advance().unwrap();
        let mut result =
            Vec::with_capacity(plaintext.len() + AES_128_GCM.tag_len() + AES_128_GCM.nonce_len());
        result.extend_from_slice(nonce.as_ref());
        result.extend_from_slice(plaintext);

        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut result[NONCE_LEN..])
            .unwrap();
        result.extend_from_slice(tag.as_ref());

        result
    }
}

pub(crate) struct RingGcmBlockDecryptor {
    key: LessSafeKey,
}

impl RingGcmBlockDecryptor {
    pub(crate) fn new(key_bytes: &[u8]) -> Self {
        let key = UnboundKey::new(&AES_128_GCM, key_bytes).unwrap();

        Self {
            key: LessSafeKey::new(key),
        }
    }

    fn new_from_less_safe_key(key: LessSafeKey) -> Self {
        Self { key }
    }
}

impl BlockDecryptor for RingGcmBlockDecryptor {
    fn decrypt(&self, length_and_ciphertext: &[u8], aad: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(
            length_and_ciphertext.len() - AES_128_GCM.tag_len() - AES_128_GCM.nonce_len(),
        );
        result.extend_from_slice(&length_and_ciphertext[AES_128_GCM.nonce_len()..]);

        let nonce = ring::aead::Nonce::try_assume_unique_for_key(
            &length_and_ciphertext[0..AES_128_GCM.nonce_len()],
        )
        .unwrap();

        self.key
            .open_in_place(nonce, Aad::from(aad), &mut result)
            .unwrap();

        result
    }
}

#[cfg(test)]
mod tests {
    use std::{
        hint::black_box,
        time::{Duration, Instant},
    };

    use ring::aead::{Aad, LessSafeKey, UnboundKey, AES_128_GCM};

    #[test]
    fn bench_ring_encdec() {
        // Pick a block large enough to avoid measuring start-up cost but small
        // enough to fit into any reasonable L1 cache
        const BLOCK_BYTES: usize = 16 * (1 << 10); // 16 KiB
        let mut input: [u8; BLOCK_BYTES] = [0; BLOCK_BYTES];
        for i in 0..input.len() {
            input[i] = i as u8;
        }

        let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, b"0123456789abcdef").unwrap());
        let nonce = || ring::aead::Nonce::assume_unique_for_key([0; 12]);

        // Benchmark the decryptor for some amount of time and see how much data has been processed
        const TEST_MS: usize = 2000;
        let mut enc_data: usize = 0;
        let mut dec_data: usize = 0;
        let mut enc_time: Duration = Duration::from_micros(0);
        let mut dec_time = Duration::from_micros(0);

        // Warmup
        for _ in 0..1000 {
            let tag = black_box(
                key.seal_in_place_separate_tag(nonce(), Aad::empty(), &mut input)
                    .unwrap(),
            );

            black_box(
                key.open_in_place_separate_tag(nonce(), Aad::empty(), tag, &mut input, 0..)
                    .unwrap(),
            );
        }

        loop {
            let start = Instant::now();
            let tag = black_box(
                key.seal_in_place_separate_tag(
                    black_box(nonce()),
                    black_box(Aad::empty()),
                    black_box(&mut input),
                )
                .unwrap(),
            );
            enc_time += start.elapsed();
            enc_data += input.len();

            let start = Instant::now();
            black_box(
                key.open_in_place_separate_tag(
                    black_box(nonce()),
                    black_box(Aad::empty()),
                    black_box(tag),
                    black_box(&mut input),
                    black_box(0..),
                )
                .unwrap(),
            );
            dec_time += start.elapsed();
            dec_data += input.len();

            if enc_time.as_millis() as usize >= TEST_MS && dec_time.as_millis() as usize >= TEST_MS
            {
                break;
            }
        }

        println!(
            "Encryption performance: {} MiB processed in {} ms, throughput is {} MiB/s",
            (enc_data as f32 / (1 << 20) as f32),
            enc_time.as_millis(),
            enc_data as f32 / (1 << 20) as f32 / enc_time.as_secs_f32()
        );

        println!(
            "Decryption performance: {} MiB processed in {} ms, throughput is {} MiB/s",
            (dec_data as f32 / (1 << 20) as f32),
            dec_time.as_millis(),
            dec_data as f32 / (1 << 20) as f32 / dec_time.as_secs_f32()
        );
    }
}
