use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use collector as vtpm;
use evidence_protocol::Evidence;
use evidence_protocol::Nonce;
use evidence_protocol::{AttestationRequest, AttestationResponse, IMALogEntry, ModuleLoadOrder};
mod collector;
use log::{debug, error, info};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::X509NameBuilder;
use openssl::x509::X509;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

pub struct Attester;

impl Attester {
    fn read_ima_measurements() -> Result<Vec<IMALogEntry>, Box<dyn Error>> {
        let path = "/sys/kernel/security/ima/ascii_runtime_measurements";
        let file = File::open(path)?;
        Self::parse_ima_measurements(io::BufReader::new(file))
    }

    fn parse_ima_measurements(
        mut reader: impl BufRead,
    ) -> Result<Vec<IMALogEntry>, Box<dyn Error>> {
        let mut measurements = Vec::new();
        let mut total_bytes = 0;
        loop {
            let mut line = String::new();
            let read = (&mut reader).take(8193).read_line(&mut line)?;
            if read == 0 {
                break;
            }
            total_bytes += read;
            if measurements.len() >= 16384 || total_bytes > 2 * 1024 * 1024 {
                return Err("IMA log exceeds profile size limit".into());
            }
            if line.len() > 8192 {
                return Err("IMA entry exceeds size limit".into());
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            if parts.len() < 5 {
                return Err("Incomplete IMA measurement".into());
            }
            if parts[2] != "ima-ng" && parts[2] != "ima-sig" {
                return Err("Unsupported IMA template".into());
            }
            let filedata: Vec<&str> = parts[3].splitn(2, ':').collect();
            if filedata.len() != 2 {
                return Err("Invalid IMA measurement".into());
            }
            let filename_hint = parts[4].to_string();
            let name = filename_hint
                .rsplit('/')
                .next()
                .unwrap_or(&filename_hint)
                .to_string();
            measurements.push(IMALogEntry {
                name,
                pcr: parts[0].parse()?,
                template_hash: parts[1].to_string(),
                ima_template: parts[2].to_string(),
                filedata_alg: filedata[0].to_string(),
                filedata_hash: filedata[1].to_string(),
                filename_hint,
            });
        }
        if measurements.is_empty() {
            return Err("No IMA measurements found".into());
        }
        Ok(measurements)
    }

    fn module_load_order(measurements: &[IMALogEntry]) -> ModuleLoadOrder {
        let kernel = measurements
            .iter()
            .find_map(|measurement| {
                let (_, module_path) = measurement.filename_hint.split_once("/modules/")?;
                let (version, _) = module_path.split_once('/')?;
                Some(version.to_string())
            })
            .unwrap_or_default();
        ModuleLoadOrder {
            kernel,
            order: measurements
                .iter()
                .map(|measurement| measurement.name.clone())
                .collect(),
        }
    }

    pub fn gather_evidence(
        nonce: &Nonce,
        certificate: &X509,
        algorithms: Arc<Vec<vtpm::Algorithm>>,
    ) -> Result<Evidence, Box<dyn Error>> {
        let mut last_error = String::from("unstable evidence snapshot");
        for _ in 0..3 {
            let attempt = (|| -> Result<Evidence, Box<dyn Error>> {
                let report = vtpm::get_report()?;
                let measurements = Self::read_ima_measurements()?;
                let binding = Evidence::ima_binding(&measurements)?;
                let mut quote_nonce = nonce.clone();
                quote_nonce.extend_binding(&certificate.to_der()?, &binding);
                let quote = vtpm::get_quote(quote_nonce.as_bytes(), algorithms.to_vec())?;
                let order = Self::module_load_order(&measurements);
                let evidence =
                    Evidence::new(report, quote, serde_json::Value::Null, order, measurements);
                // TPM quote and PCR read are separate commands. Verify their
                // signed digest and selection before returning a snapshot.
                evidence_core::verify_snapshot(
                    &evidence,
                    nonce.as_bytes(),
                    &certificate.to_der()?,
                )?;
                if evidence.ima_measurements != Self::read_ima_measurements()? {
                    return Err("IMA changed during quote collection".into());
                }
                Ok(evidence)
            })();
            match attempt {
                Ok(evidence) => return Ok(evidence),
                Err(e) => {
                    last_error = e.to_string();
                    log::warn!("Retrying inconsistent evidence snapshot: {last_error}");
                }
            }
        }
        Err(format!("Snapshot unavailable after 3 attempts: {last_error}").into())
    }
}

async fn tee_report_route(
    data: web::Json<AttestationRequest>,
    certificate: Arc<X509>,
    algorithms: Arc<Vec<vtpm::Algorithm>>,
    collector: Arc<Semaphore>,
) -> impl Responder {
    let nonce = match Nonce::read(&data.nonce) {
        Ok(nonce) => nonce,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };
    // Fail immediately when busy. A timed-out blocking task retains its permit
    // until the TPM call actually finishes; it cannot spawn unbounded workers.
    let permit = match collector.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return HttpResponse::ServiceUnavailable().body("Evidence collector busy"),
    };
    let cert = Arc::clone(&certificate);
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        Attester::gather_evidence(&nonce, &cert, algorithms).map_err(|e| e.to_string())
    });
    let evidence = match tokio::time::timeout(Duration::from_secs(20), task).await {
        Ok(Ok(Ok(evidence))) => evidence,
        other => {
            error!("Evidence collection failed or exceeded its deadline: {other:?}");
            return HttpResponse::ServiceUnavailable()
                .body("Consistent evidence snapshot unavailable");
        }
    };
    let response = AttestationResponse::new(
        evidence,
        match certificate.to_pem() {
            Ok(pem) => pem,
            Err(_) => return HttpResponse::InternalServerError().finish(),
        },
    );
    HttpResponse::Ok().json(response)
}

fn write_private_key(path: &Path, private_key: &PKey<Private>) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&private_key.private_key_to_pem_pkcs8()?)?;
    Ok(())
}

fn certificate_covers_host(certificate: &X509, hostname: &str) -> bool {
    let Some(names) = certificate.subject_alt_names() else {
        return false;
    };
    match hostname.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => names
            .iter()
            .any(|name| name.ipaddress() == Some(ip.octets().as_slice())),
        Ok(IpAddr::V6(ip)) => names
            .iter()
            .any(|name| name.ipaddress() == Some(ip.octets().as_slice())),
        Err(_) => names.iter().any(|name| {
            name.dnsname()
                .is_some_and(|dns| dns.eq_ignore_ascii_case(hostname))
        }),
    }
}

fn validate_leaf_certificate(certificate: &X509) -> Result<(), Box<dyn Error>> {
    let der = certificate.to_der()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| format!("Invalid collector certificate: {e}"))?;
    if parsed
        .basic_constraints()?
        .is_some_and(|constraints| constraints.value.ca)
    {
        return Err(concat!(
            "Collector certificate has CA:TRUE; expected the HTTPS leaf certificate. ",
            "Use the same certificate directory as Nginx (normally /etc/confido)."
        )
        .into());
    }
    Ok(())
}

fn generate_certificate(
    hostname: &str,
) -> Result<(X509, PKey<Private>), openssl::error::ErrorStack> {
    // Generate a new 2048-bit RSA private key
    let rsa = Rsa::generate(2048)?;
    let private_key = PKey::from_rsa(rsa)?;

    // Build the certificate name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::COMMONNAME, hostname)?;
    let name = name_builder.build();

    // Build the certificate
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&private_key)?;
    let mut san = SubjectAlternativeName::new();
    if hostname.parse::<IpAddr>().is_ok() {
        san.ip(hostname);
    } else {
        san.dns(hostname);
    }
    let extension = san.build(&builder.x509v3_context(None, None))?;
    builder.append_extension(extension)?;
    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;
    builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;

    // Set the not_before and not_after dates for the certificate
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    builder.sign(&private_key, MessageDigest::sha256())?;
    let certificate = builder.build();
    let certificate_pem = certificate.to_pem()?;
    let certificate_pem_str = String::from_utf8_lossy(&certificate_pem);
    debug!("{}", certificate_pem_str);

    Ok((certificate, private_key))
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let matches = clap::App::new("Attestor Evidence Collector")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Collects challenge-bound evidence with the configured HTTPS certificate")
        .arg(
            clap::Arg::new("host:port")
                .help("Sets the host and port in the format host:port")
                .required(true)
                .index(1),
        )
        .arg(
            clap::Arg::new("certs")
                .help("Sets the certificate folder")
                .required(true)
                .index(2),
        )
        .arg(
            clap::Arg::new("algo")
                .help("Sets the algorithm")
                .required(true)
                .index(3)
                .multiple_values(true)
                .possible_values(["sha1", "sha256"]),
        )
        .arg(
            clap::Arg::new("tls-hostname")
                .long("tls-hostname")
                .help("DNS name or IP address used by the HTTPS application")
                .takes_value(true),
        )
        .arg(
            clap::Arg::new("check-config")
                .long("check-config")
                .help("Prepare and validate certificate configuration without starting the server"),
        )
        .get_matches();

    let host_port = matches.value_of("host:port").unwrap_or("127.0.0.1:8080");
    let certs_folder = matches.value_of("certs").unwrap_or("./");
    let tls_hostname = matches.value_of("tls-hostname");
    std::fs::create_dir_all(certs_folder)?;

    // Save private key and certificate into the provided certs_folder
    let private_key_path = format!("{}/private_key.pem", certs_folder);
    let certificate_path = format!("{}/certificate.pem", certs_folder);

    let key_exists = Path::new(&private_key_path).exists();
    let cert_exists = Path::new(&certificate_path).exists();
    if key_exists != cert_exists {
        return Err("The certificate and private key must both exist, or both be absent".into());
    }

    let (certificate, private_key) = if key_exists {
        // Read the existing private key and certificate.
        if fs::symlink_metadata(&private_key_path)?
            .file_type()
            .is_symlink()
        {
            return Err("The private key path must not be a symlink".into());
        }
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))?;
        let private_key_pem = fs::read(&private_key_path)?;
        let private_key = PKey::private_key_from_pem(&private_key_pem)?;

        let certificate_pem = std::fs::read(&certificate_path)?;
        let certificate = X509::from_pem(&certificate_pem)?;

        (certificate, private_key)
    } else {
        // Generate new private key and certificate
        let (certificate, private_key) = generate_certificate(tls_hostname.unwrap_or("localhost"))?;

        // Save private key and certificate into the provided certs_folder
        write_private_key(Path::new(&private_key_path), &private_key)?;
        fs::write(&certificate_path, certificate.to_pem()?)?;

        info!("Private key saved to: {}", private_key_path);
        info!("Certificate saved to: {}", certificate_path);

        (certificate, private_key)
    };

    validate_leaf_certificate(&certificate)?;
    if !certificate.public_key()?.public_eq(&private_key) {
        return Err("The certificate does not match the private key".into());
    }
    if let Some(hostname) = tls_hostname {
        if !certificate_covers_host(&certificate, hostname) {
            return Err(format!(
                "The certificate does not have a subject alternative name for {hostname}"
            )
            .into());
        }
    }

    if matches.is_present("check-config") {
        println!("Certificate configuration valid: {certificate_path}");
        return Ok(());
    }

    let certificate = Arc::new(certificate);

    let mut algorithms = Vec::new();
    if let Some(values) = matches.values_of("algo") {
        for algo in values {
            match algo {
                "sha1" => algorithms.push(vtpm::Algorithm::Sha1),
                "sha256" => algorithms.push(vtpm::Algorithm::Sha256),
                _ => unreachable!(),
            }
        }
    }

    if algorithms.is_empty() {
        algorithms.push(vtpm::Algorithm::Sha256);
    }

    let algorithms = Arc::new(algorithms);
    let collector = Arc::new(Semaphore::new(1));

    info!("Starting server at {}", host_port);
    HttpServer::new(move || {
        let certificate = Arc::clone(&certificate);
        let algorithms = Arc::clone(&algorithms);
        let collector = Arc::clone(&collector);
        App::new()
            .wrap(actix_web::middleware::DefaultHeaders::new().add(("Cache-Control", "no-store")))
            .app_data(web::JsonConfig::default().limit(1024))
            .route(
                "/tee-report",
                web::post().to(move |data: web::Json<AttestationRequest>| {
                    info!("http server report route called");
                    tee_report_route(
                        data,
                        Arc::clone(&certificate),
                        Arc::clone(&algorithms),
                        Arc::clone(&collector),
                    )
                }),
            )
            .route(
                "/tee-report",
                web::head().to(|| async { HttpResponse::NoContent().finish() }),
            )
    })
    .bind(host_port)?
    .run()
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests;
