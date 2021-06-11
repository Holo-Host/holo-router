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
    serializer.serialize_str(&public_key::to_base36_id(&public_key))
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

fn main() -> Fallible<()> {
    let config_path = env::var("HPOS_CONFIG_PATH")?;
    let registry_url = env::var("ROUTER_REGISTRY_URL")?;
    let config_json = fs::read(config_path)?;
    let Config::V1 { seed, .. } = serde_json::from_slice(&config_json)?;

    let holochain_secret_key = SecretKey::from_bytes(&seed)?;
    let holochain_public_key = PublicKey::from(&holochain_secret_key);
    let holochain_keypair = Keypair {
        public: holochain_public_key,
        secret: holochain_secret_key,
    };

    let zerotier_identity =
        Identity::try_from(&fs::read_to_string("/var/lib/zerotier-one/identity.secret")?[..])?;
    let zerotier_address = zerotier_identity.address.clone();
    let zerotier_keypair: Keypair = zerotier_identity.try_into()?;

    let zt_string = serde_json::to_string(&zerotier_address)?;
    let hc_string = public_key::to_base36_id(&holochain_public_key);

    println!("holochain_public_key: {}", hc_string);
    println!("zerotier_address: {}", zt_string);

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
        .post(&registry_url)
        .headers(headers)
        .body(payload_bytes)
        .send()?;

    Ok(())
}
