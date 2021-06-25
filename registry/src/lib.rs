use ed25519_dalek::*;
use failure::Error;
use serde::*;
use wasm_bindgen::prelude::*;

use std::convert::TryFrom;

#[derive(Deserialize)]
struct VerifyPayloadInput {
    payload: String,
    holochain_public_key: String,
    holochain_signature: String,
    zerotier_public_key: String,
    zerotier_signature: String,
}

fn verify_input_inner(input: VerifyPayloadInput) -> Result<(), Error> {
    let holochain_public_key_bytes = base64::decode(&input.holochain_public_key)?;
    let holochain_signature_bytes = base64::decode(&input.holochain_signature)?;
    let zerotier_public_key_bytes = base64::decode(&input.zerotier_public_key)?;
    let zerotier_signature_bytes = base64::decode(&input.zerotier_signature)?;

    let holochain_public_key = PublicKey::from_bytes(&holochain_public_key_bytes)?;
    let holochain_signature = Signature::from_bytes(&holochain_signature_bytes)?;
    let zerotier_public_key = zerotier::PublicKey::try_from(&zerotier_public_key_bytes[..])?;
    let zerotier_signature = Signature::from_bytes(&zerotier_signature_bytes)?;

    let payload_bytes = input.payload.as_bytes();

    holochain_public_key.verify(payload_bytes, &holochain_signature)?;
    zerotier_public_key
        .ed
        .verify(payload_bytes, &zerotier_signature)?;

    Ok(())
}

#[wasm_bindgen]
pub fn verify_input(input: JsValue) -> bool {
    match verify_input_inner(input.into_serde().unwrap()) {
        Ok(()) => true,
        Err(_) => false,
    }
}
