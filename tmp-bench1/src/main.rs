use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes128Gcm, Nonce, Key};
use std::time::SystemTime;
use rand::prelude::*;

fn main() {
    const GCM_NONCE_LENGTH: usize = 12;

    const P_LEN: usize = 1 * 1024 * 1024;

    let mut input: [u8; P_LEN] = [0; P_LEN];
    for i in 1..input.len() {
        input[i] = i as u8;
    }

    let mut prev_total: usize = 0;
    let mut new_total: usize = 0;
    let ini_time = SystemTime::now();
    let mut prev_time = SystemTime::now();
    let mut counter: i32 = 0;

    let key_code: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let key = Key::<Aes128Gcm>::from_slice(&key_code[..]);
    let cipher = Aes128Gcm::new(&key);

    let aad: &[u8] = "abcdefgh".as_bytes();
    let plaintext = Payload {
        msg: &input[..],
        aad: &aad[..],
    };


    println!("Plaintext length: {}", input.len());

    let mut rng = rand::thread_rng();
    let mut nonce: [u8; GCM_NONCE_LENGTH] = [0; GCM_NONCE_LENGTH];
    nonce.shuffle(&mut rng);
    let nonce = Nonce::from_slice(&nonce[..]);

    let ciphertext: Vec<u8>;

    // Encrypt
    match cipher.encrypt(&nonce, plaintext) {
        Ok(ciphertxt) => {
            println!("Ciphertext length: {}", ciphertxt.len());
            ciphertext = ciphertxt;
        },
        Err(e) => panic!("{}", e),
    }

    loop {
        let cipher_text = Payload {
            msg: &ciphertext[..],
            aad: &aad[..],
        };

        match cipher.decrypt(&nonce, cipher_text) {
            Ok(decrypted) => new_total += decrypted.len(),
            Err(e) => panic!("{}", e),
        }

        counter += 1;

        if counter % 1000 == 0 {
            let tdelta = prev_time.elapsed().unwrap().as_millis();
            if tdelta > 3000 {
                let ddelta: usize = new_total - prev_total;
                let rate: f64 = (ddelta as f64) / (tdelta as f64) / 1024.0; // ~ MB/sec
                println!("Rate: {} MB/sec. Counter: {}. Total, MB: {}. Time: {}",
                         rate, counter, new_total / 1024 / 1024, (ini_time.elapsed().unwrap().as_millis()) / 1000);
                prev_time = SystemTime::now();
                prev_total = new_total;
            }
        }
    }
}
