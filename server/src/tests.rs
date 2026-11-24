use super::*;

#[test]
fn reads_ima_order_and_digest_metadata() {
    let log = concat!(
        "10 abc ima-ng sha256:def boot_aggregate\n",
        "10 123 ima-ng sha256:456 /lib/modules/6.8.0/kernel/example.ko\n"
    );
    let entries = Attester::parse_ima_measurements(log.as_bytes()).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "boot_aggregate");
    assert_eq!(entries[1].name, "example.ko");
    assert_eq!(entries[1].pcr, 10);
    assert_eq!(entries[1].template_hash, "123");
    assert_eq!(entries[1].filedata_alg, "sha256");
    assert_eq!(entries[1].filedata_hash, "456");
    assert_eq!(
        entries[1].filename_hint,
        "/lib/modules/6.8.0/kernel/example.ko"
    );
    let order = Attester::module_load_order(&entries);
    assert_eq!(order.kernel, "6.8.0");
    assert_eq!(order.order, ["boot_aggregate", "example.ko"]);
}

#[test]
fn rejects_empty_truncated_and_unsupported_measurements() {
    for log in [
        "",
        "\n",
        "10 abc ima-ng\n",
        "10 abc ima-ng invalid /file\n",
        "10 abc ima-buf sha256:def /file\n",
        "bad abc ima-ng sha256:def /file\n",
    ] {
        assert!(
            Attester::parse_ima_measurements(log.as_bytes()).is_err(),
            "{log:?}"
        );
    }
}

#[test]
fn reads_ima_sig_without_reconstructing_or_dropping_its_template_hash() {
    let entries = Attester::parse_ima_measurements(
        "10 abc ima-sig sha256:def /lib/module.ko 030204...\n".as_bytes(),
    )
    .unwrap();
    assert_eq!(entries[0].ima_template, "ima-sig");
    assert_eq!(entries[0].template_hash, "abc");
}

#[test]
fn creates_private_keys_with_owner_only_permissions() {
    let rsa = Rsa::generate(2048).unwrap();
    let key = PKey::from_rsa(rsa).unwrap();
    let path = std::env::temp_dir().join(format!(
        "attestor-key-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    write_private_key(&path, &key).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(write_private_key(&path, &key).is_err());
    let saved = PKey::private_key_from_pem(&fs::read(&path).unwrap()).unwrap();
    assert!(saved.public_eq(&key));
    fs::remove_file(path).unwrap();
}

#[test]
fn generated_certificate_has_requested_subject_alternative_name() {
    for hostname in ["collector.example.test", "127.0.0.1"] {
        let (certificate, private_key) = generate_certificate(hostname).unwrap();
        validate_leaf_certificate(&certificate).unwrap();
        let der = certificate.to_der().unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(&der).unwrap();
        assert!(!parsed.basic_constraints().unwrap().unwrap().value.ca);
        assert!(certificate_covers_host(&certificate, hostname));
        assert!(!certificate_covers_host(&certificate, "other.example"));
        assert!(certificate.public_key().unwrap().public_eq(&private_key));
    }
}

#[actix_web::test]
async fn rejects_invalid_nonce_oversize_and_busy_before_tpm_access() {
    let (certificate, _) = generate_certificate("localhost").unwrap();
    let certificate = Arc::new(certificate);
    let algorithms = Arc::new(vec![vtpm::Algorithm::Sha256]);
    // Zero slots simulates an occupied collector without calling real TPM APIs.
    let collector = Arc::new(Semaphore::new(0));
    let app = actix_web::test::init_service(
        App::new()
            .wrap(actix_web::middleware::DefaultHeaders::new().add(("Cache-Control", "no-store")))
            .app_data(web::JsonConfig::default().limit(1024))
            .route(
                "/tee-report",
                web::post().to(move |data: web::Json<AttestationRequest>| {
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
            ),
    )
    .await;
    let probe = actix_web::test::TestRequest::default()
        .method(actix_web::http::Method::HEAD)
        .uri("/tee-report")
        .to_request();
    let response = actix_web::test::call_service(&app, probe).await;
    assert_eq!(response.status().as_u16(), 204);
    for (nonce, expected) in [
        ("bad!".to_string(), 400),
        (base64::encode([0; 32]), 503),
        ("x".repeat(2048), 413),
    ] {
        let request = actix_web::test::TestRequest::post()
            .uri("/tee-report")
            .set_json(serde_json::json!({"nonce":nonce}))
            .to_request();
        let response = actix_web::test::call_service(&app, request).await;
        assert_eq!(response.status().as_u16(), expected);
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    }
}

#[test]
fn rejects_cached_ca_certificate() {
    let (leaf, key) = generate_certificate("localhost").unwrap();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(leaf.subject_name()).unwrap();
    builder.set_issuer_name(leaf.issuer_name()).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder.set_not_before(leaf.not_before()).unwrap();
    builder.set_not_after(leaf.not_after()).unwrap();
    builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    let error = validate_leaf_certificate(&builder.build()).unwrap_err();
    assert!(error.to_string().contains("CA:TRUE"));
}
