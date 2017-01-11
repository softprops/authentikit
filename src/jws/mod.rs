extern crate base64;
extern crate serde_json;

use openssl::crypto::pkey::PKey;
use openssl::crypto::hash::hash;
use openssl::crypto::hash::Type::SHA256;
use std::time;
use std::time::{Duration, SystemTime};
use std::ops::Add;

include!(concat!(env!("OUT_DIR"), "/jws/mod.rs"));

fn base64_enc(bytes: &[u8]) -> String {
    let enc = base64::encode_mode(bytes, base64::Base64Mode::UrlSafe);
    enc[..].trim_right_matches('=').to_owned()
}

// https://developers.google.com/identity/protocols/OAuth2ServiceAccount#authorizingrequests
/// encodes header and claims with some signing function
pub fn encode_with<F>(header: &mut Header, claims: &mut Claims, signer: F) -> String
    where F: FnOnce(&[u8]) -> Vec<u8>
{
    let now = SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();
    if claims.iat == 0 {
        claims.iat = now.as_secs() as i64;
    }
    if claims.exp == 0 {
        claims.exp = now.add(Duration::new(60 * 60, 0)).as_secs() as u32;
    }
    let enc_header = base64_enc(serde_json::to_string(&header).unwrap().as_bytes());
    let enc_claims = base64_enc(serde_json::to_string(&claims).unwrap().as_bytes());
    let signature_base = format!("{}.{}", enc_header, enc_claims);
    let signature = signer(signature_base.as_bytes());
    format!("{}.{}", signature_base, base64_enc(&signature))
}

/// Encode encodes a signed JWS with provided header and claim set
pub fn encode(header: &mut Header, claims: &mut Claims, key: PKey) -> String {
    encode_with(header,
                claims,
                |bytes| key.sign_with_hash(&hash(SHA256, bytes), SHA256))
}
