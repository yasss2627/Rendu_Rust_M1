use std::error::Error;
use std::sync::Arc;
use std::process::Command;
use std::collections::HashSet;
use regex::Regex;

use tokio::net::TcpStream;
use reqwest::Client;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;
use tokio_rustls::{rustls, TlsConnector};
use tokio_rustls::rustls::OwnedTrustAnchor;
use webpki_roots::TLS_SERVER_ROOTS;
use x509_parser::prelude::*;
use hex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let domain = "google.com";
    let port = 443;

    println!("--- Résolution DNS ---");
    show_dns_info(domain).await?;

    println!("\n--- Connexion TCP et requête HTTP ---");
    show_connection_info(domain, port).await?;

    println!("\n--- Traceroute ---");
    show_traceroute(domain)?;

    Ok(())
}

// --- Résolution DNS ---
async fn show_dns_info(domain: &str) -> Result<(), Box<dyn Error>> {
    let resolver_config = ResolverConfig::default();
    let resolver_opts = ResolverOpts::default();
    let resolver = TokioAsyncResolver::tokio(resolver_config.clone(), resolver_opts)?;

    let response = resolver.lookup_ip(domain).await?;
    println!("IP(s) du serveur :");
    for ip in response.iter() {
        println!("  {}", ip);
    }

    println!("Serveurs DNS utilisés (IPv4 uniquement) :");
    for ns in resolver_config.name_servers() {
        let ip = ns.socket_addr.ip();
        if ip.is_ipv4() {
            println!("  {}", ip);
        }
    }

    Ok(())
}

// --- Connexion TCP/TLS + Requête HTTP + Certificat ---
async fn show_connection_info(domain: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let addr = format!("{}:{}", domain, port);
    let stream = TcpStream::connect(&addr).await?;
    let local = stream.local_addr()?;
    let peer = stream.peer_addr()?;

    println!("IP et port source : {}:{}", local.ip(), local.port());
    println!("IP et port destination : {}:{}", peer.ip(), peer.port());
    println!();

    // TLS
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(
        TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        })
    );

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let domain_rustls = rustls::ServerName::try_from(domain)?;
    let tls_stream = connector.connect(domain_rustls, stream).await?;

    // Requête HTTP
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let url = format!("https://{}", domain);
    let response = client.get(&url).send().await?;
    println!("Status HTTP: {}", response.status());

    if let Some(content_type) = response.headers().get("content-type") {
        println!("Content-Type: {}", content_type.to_str()?);
    }

    // Certificat
    if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
        if !certs.is_empty() {
            let cert = &certs[0];
            println!("\n--- Certificat TLS ---");
            if let Ok((_rem, x509)) = parse_x509_certificate(&cert.0) {
                println!("Sujet    : {}", x509.subject());
                println!("Émis par : {}", x509.issuer());
                let spki_bytes = x509.subject_pki.raw;
                println!("Clé publique (hexadécimal) : {}", hex::encode(spki_bytes));
            }
        }
    }

    Ok(())
}

// --- Traceroute ---
fn show_traceroute(domain: &str) -> Result<(), Box<dyn Error>> {
    // Exécution de traceroute avec IP numériques
    let output = Command::new("traceroute").arg("-n").arg(domain).output();

    let stdout = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => {
            // fallback sur tracepath si traceroute absent / échoue
            let tp = Command::new("tracepath").arg(domain).output()?;
            if !tp.status.success() {
                return Err("Impossible d'exécuter 'traceroute' ou 'tracepath'.".into());
            }
            String::from_utf8_lossy(&tp.stdout).to_string()
        }
    };

    // Regex pour extraire IPv4 et IPv6
    let re_ip = Regex::new(r"((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})")?;
    let mut ips: Vec<String> = Vec::new();
    let mut seen = HashSet::new();

    for line in stdout.lines() {
        if line.trim().is_empty() { continue; }
        if line.contains('*') && !re_ip.is_match(line) { continue; }

        for cap in re_ip.captures_iter(line) {
            let ip = cap.get(1).unwrap().as_str().to_string();
            if Some(&ip) != ips.last() && seen.insert(ip.clone()) {
                ips.push(ip);
            }
        }
    }

    if ips.is_empty() {
        println!("Aucune IP récupérée (tous les sauts non-répondants).");
    } else {
        println!("IPs traversées :");
        for (i, ip) in ips.iter().enumerate() {
            println!("  {}: {}", i + 1, ip);
        }
    }

    Ok(())
}