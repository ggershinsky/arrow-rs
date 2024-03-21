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

use aes_gcm::{aead::{Aead, KeyInit, Payload}, Nonce, Key, Aes128Gcm, AesGcm};
use aes_gcm::aead::consts::U12;
use aes_gcm::aes::Aes128;
use crate::encryption::GCM_NONCE_LENGTH;
use rand::prelude::*;

pub trait BlockEncryptor {
    fn encrypt(&mut self,  plaintext: &[u8], aad: &[u8]) -> Vec<u8> ;
}

pub trait BlockDecryptor {
    fn decrypt(&self,  length_and_ciphertext: &[u8],  aad: &[u8]) -> Vec<u8> ;
}

pub(crate) struct GcmBlockEncryptor {
    rng: ThreadRng,
    cipher: AesGcm<Aes128, U12> // todo support other key sizes
}

impl GcmBlockEncryptor {
    pub(crate) fn new(key_bytes: &[u8]) -> Self {
        let key_size = key_bytes.len(); //todo check len
        let key_vec = Vec::from(key_bytes);
        let key = Key::<Aes128Gcm>::from_slice(&key_vec[..]);

        Self {
            rng: rand::thread_rng(),
            cipher: Aes128Gcm::new(&key)
        }
    }
}

impl BlockEncryptor for GcmBlockEncryptor {
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
            },
            Err(e) => panic!("Failed to encrypt {}", e),
        }
    }
}

pub(crate) struct GcmBlockDecryptor {
    cipher: AesGcm<Aes128, U12> // todo support other key sizes
}

impl GcmBlockDecryptor {
    pub(crate) fn new(key_bytes: &[u8]) -> Self {
        let key_size = key_bytes.len(); //todo check key len
        let key_vec = Vec::from(key_bytes);
        let key = Key::<Aes128Gcm>::from_slice(&key_vec[..]);

        Self {
            cipher: Aes128Gcm::new(&key)
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
