use failure::*;
use futures::future;
use std::env;
use tokio::net::{TcpListener, TcpStream};
use tracing::*;
use tracing_futures::*;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use uuid::Uuid;

// See: https://tls.ulfheim.net
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::enums::{ContentType, ProtocolVersion};
use rustls::internal::msgs::handshake::{
    HandshakeMessagePayload, HandshakePayload, ServerNamePayload,
};

const TLS_HANDSHAKE_MAX_LENGTH: usize = 2048;
const TLS_RECORD_HEADER_LENGTH: usize = 5;

async fn peek(stream: &mut TcpStream, size: usize) -> Fallible<Vec<u8>> {
    let mut buf = vec![0; size];
    let n = stream.peek(&mut buf).await?;

    if n == size {
        Ok(buf)
    } else {
        bail!("Socket peek size mismatch: {} != {}", n, size)
    }
}

async fn splice(mut inbound: TcpStream, mut outbound: TcpStream) -> Fallible<()> {
    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = tokio::io::copy(&mut ri, &mut wo);
    let server_to_client = tokio::io::copy(&mut ro, &mut wi);

    future::try_join(client_to_server, server_to_client).await?;

    Ok(())
}

async fn splice_by_sni(mut inbound: TcpStream) -> Fallible<()> {
    let buf = peek(&mut inbound, TLS_RECORD_HEADER_LENGTH).await?;
    let mut rd = Reader::init(&buf);

    let content_type = ContentType::read(&mut rd).ok_or(err_msg("Failed to read content type"))?;
    debug!("Content type: {:?}", content_type);

    if content_type != ContentType::Handshake {
        bail!("Content type is not Handshake");
    }

    let protocol_version =
        ProtocolVersion::read(&mut rd).ok_or(err_msg("Failed to read protocol version"))?;
    debug!("Protocol version: {:?}", protocol_version);

    let handshake_size =
        usize::from(u16::read(&mut rd).ok_or(err_msg("Failed to read handshake size"))?);
    debug!("Handshake size: {:?}", handshake_size);

    if handshake_size > TLS_HANDSHAKE_MAX_LENGTH {
        bail!(
            "Handshake size is {}, while max is {}",
            handshake_size,
            TLS_HANDSHAKE_MAX_LENGTH
        );
    }

    let buf = peek(&mut inbound, TLS_RECORD_HEADER_LENGTH + handshake_size).await?;
    let mut rd = Reader::init(&buf);

    rd.take(TLS_RECORD_HEADER_LENGTH);

    let handshake = HandshakeMessagePayload::read_version(&mut rd, protocol_version)
        .ok_or(err_msg("Failed to read handshake"))?;

    let client_hello = match handshake.payload {
        HandshakePayload::ClientHello(x) => x,
        _ => bail!("Handshake payload is not Client Hello"),
    };

    let sni = client_hello
        .get_sni_extension()
        .ok_or(err_msg("SNI is missing"))?;

    let hostname: &str = match &sni[0].payload {
        ServerNamePayload::HostName(x) => x.as_ref().into(),
        ServerNamePayload::Unknown(_) => bail!("SNI payload uses unknown format"),
    };

    info!("Hostname: {}", hostname);

    let holoport_domain = match env::var("HOLOPORT_DOMAIN") {
      Ok(x) => format!(".{}", x),
      Err(_) => bail!("HOLOPORT_DOMAIN env var not set"),
    };

    if !hostname.ends_with(&holoport_domain) {
        bail!("Hostname is not *{}", &holoport_domain);
    }

    let outbound_addr = format!("{}:443", hostname);
    let outbound = TcpStream::connect(outbound_addr).await?;

    splice(inbound, outbound).await
}

#[tokio::main]
async fn main() -> Fallible<()> {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    let mut listener = TcpListener::bind("[::]:443").await?;

    loop {
        let (inbound, inbound_addr) = listener.accept().await?;

        let request = async move {
            debug!("Inbound IP address: {}", inbound_addr.ip());

            if let Err(e) = splice_by_sni(inbound).in_current_span().await {
                warn!("{}", e);
            }
        };

        tokio::spawn(request.instrument(info_span!("request", uuid = ?Uuid::new_v4())));
    }
}
