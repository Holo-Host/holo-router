use ed25519_dalek::*;
use failure::*;
use hpos_config_core::{public_key, Config};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Client;
use serde::*;
use zerotier::Identity;

use std::convert::{TryFrom, TryInto};
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn serialize_holochain_agent_id<S>(public_key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&public_key::holochain_pub_key_encoding(
        &public_key.to_bytes(),
    ))
}

fn serialize_instant<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u128(time.duration_since(UNIX_EPOCH).unwrap().as_millis())
}

fn signature_header(signature: &Signature) -> HeaderValue {
    base64::encode(&signature.to_bytes()[..]).parse().unwrap()
}

#[derive(Debug, Serialize)]
struct Payload {
    #[serde(serialize_with = "serialize_instant")]
    instant: SystemTime,
    #[serde(serialize_with = "serialize_holochain_agent_id")]
    holochain_agent_id: PublicKey,
    zerotier_address: zerotier::Address,
}

#[derive(Debug, Fail)]
pub enum RouterError {
    #[fail(display = "Invalid config version used. please upgrade to hpos-config v2")]
    ConfigVersionError,
}

fn main() -> Fallible<()> {
    let config_path = env::var("HPOS_CONFIG_PATH")?;
    let registry_url = env::var("ROUTER_REGISTRY_URL")?;
    let config_json = fs::read(config_path)?;
    match serde_json::from_slice(&config_json)? {
        Config::V2 { seed, .. } => {
            let holochain_secret_key = SecretKey::from_bytes(&seed)?;
            let holochain_public_key = PublicKey::from(&holochain_secret_key);
            let holochain_keypair = Keypair {
                public: holochain_public_key,
                secret: holochain_secret_key,
            };
            let zerotier_identity = Identity::try_from(
                &fs::read_to_string("/var/lib/zerotier-one/identity.secret")?[..],
            )?;
            let zerotier_address = zerotier_identity.address.clone();
            let zerotier_keypair: Keypair = zerotier_identity.try_into()?;
            let payload = Payload {
                instant: SystemTime::now(),
                holochain_agent_id: holochain_public_key,
                zerotier_address: zerotier_address,
            };
            let payload_bytes = serde_json::to_vec(&payload)?;
            let holochain_signature = holochain_keypair.sign(&payload_bytes[..]);
            let zerotier_signature = zerotier_keypair.sign(&payload_bytes[..]);
            let mut headers = HeaderMap::new();
            headers.insert(
                HeaderName::from_static("x-holochain-signature"),
                signature_header(&holochain_signature),
            );
            headers.insert(
                HeaderName::from_static("x-zerotier-signature"),
                signature_header(&zerotier_signature),
            );
            Client::new()
                .post(&format!("{}{}", &registry_url, "/v1/update"))
                .headers(headers)
                .body(payload_bytes)
                .send()?;
            return Ok(());
        }
        _ => return Err(RouterError::ConfigVersionError.into()),
    }
}
