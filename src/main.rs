use std::str::FromStr;
use std::sync::Arc;
use std::{env, io};

use http::Uri;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_rustls::ConfigBuilderExt;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use rustls::SignatureScheme;

use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use rustls::sign::CertifiedKey;
use rustls_cng::signer::CngSigningKey;
use rustls_cng::store::{CertStore, CertStoreType};

fn main() {
    if let Err(e) = run_client() {
        eprintln!("FAILED: {}", e);
        std::process::exit(1);
    }
}

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

#[tokio::main]
async fn run_client() -> anyhow::Result<()> {
    let url = match env::args().nth(2) {
        Some(ref url) => Uri::from_str(url).map_err(|e| error(format!("{}", e)))?,
        None => {
            println!("Usage: client <url> <subject> <pin>");
            return Ok(());
        }
    };

    let subject = match env::args().nth(3) {
        Some(subj) => subj,
        None => {
            println!("Usage: client <url> <subject> <pin>");
            return Ok(());
        }
    };

    let pin = match env::args().nth(4) {
        Some(pin) => pin,
        None => {
            println!("Usage: client <url> <subject> <pin>");
            return Ok(());
        }
    };

    let store = CertStore::open(CertStoreType::CurrentUser, "my")?;

    let (chain, signing_key) = get_chain(&store, &subject)?;
    signing_key.key().set_pin(&pin)?;

    // Prepare the TLS client config
    let tls = rustls::ClientConfig::builder()
        .with_native_roots()?
        .with_client_cert_resolver(Arc::new(ClientCertResolver { chain, signing_key }));

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();

    let client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    let fut = async move {
        let res = client
            .get(url)
            .await
            .map_err(|e| error(format!("Could not get: {:?}", e)))?;
        println!("Status:\n{}", res.status());
        println!("Headers:\n{:#?}", res.headers());

        let body = res
            .into_body()
            .collect()
            .await
            .map_err(|e| error(format!("Could not get body: {:?}", e)))?
            .to_bytes();

        println!("Body:\n{}", String::from_utf8_lossy(&body));

        Ok(())
    };

    fut.await
}

#[derive(Debug)]
pub struct ClientCertResolver {
    chain: Vec<CertificateDer<'static>>,
    signing_key: Arc<CngSigningKey>,
}

fn get_chain(
    store: &CertStore,
    name: &str,
) -> anyhow::Result<(Vec<CertificateDer<'static>>, Arc<CngSigningKey>)> {
    let contexts = store.find_by_subject_str(name)?;
    println!("{:?}", name);
    let context = contexts
        .first()
        .ok_or_else(|| anyhow::Error::msg("No client cert"))?;
    let key = context.acquire_key()?;
    let signing_key = CngSigningKey::new(key)?;
    let chain = context
        .as_chain_der()?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok((chain, Arc::new(signing_key)))
}

impl ResolvesClientCert for ClientCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        for scheme in self.signing_key.supported_schemes() {
            if sigschemes.contains(scheme) {
                return Some(Arc::new(CertifiedKey {
                    cert: self.chain.clone(),
                    key: self.signing_key.clone(),
                    ocsp: None,
                }));
            }
        }
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}
