//! Tests end to end request body creation from a LoginCredentials

#![allow(missing_docs)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use rsa::pkcs8::EncodePrivateKey;

use secrecy::SecretBox;
use snowwt::{KeypairAuth, LoginCredentials, UnixSeconds};

fn benchmark(c: &mut Criterion) {
    let privkey = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();

    let p8 = privkey.to_pkcs8_pem(Default::default()).unwrap();
    let p8_enc = privkey
        .to_pkcs8_encrypted_pem(&mut rand::thread_rng(), "hello", Default::default())
        .unwrap();

    let password = black_box(LoginCredentials::new(
        "typical_length",
        "username",
        snowwt::LoginAuth::password("Password"),
    ));
    let keypair_npw = black_box(LoginCredentials::new(
        "typical_length",
        "username",
        snowwt::LoginAuth::Keypair(KeypairAuth::new(None, p8.as_str().into()).expect("ok")),
    ));
    let keypair_pw = black_box(LoginCredentials::new(
        "typical_length",
        "username",
        snowwt::LoginAuth::Keypair(
            KeypairAuth::new(
                Some(SecretBox::new(Box::from("hello".as_bytes()))),
                p8_enc.as_str().into(),
            )
            .expect("ok"),
        ),
    ));

    c.bench_function("password", |c| {
        c.iter(|| {
            black_box(
                serde_json::to_string(
                    &password
                        .generate_login_request(UnixSeconds(0), UnixSeconds(0))
                        .unwrap(),
                )
                .unwrap(),
            )
        })
    });

    c.bench_function("keypair_npw", |c| {
        c.iter(|| {
            black_box(
                serde_json::to_string(
                    &keypair_npw
                        .generate_login_request(UnixSeconds(0), UnixSeconds(0))
                        .unwrap(),
                )
                .unwrap(),
            )
        })
    });

    c.bench_function("keypair_pw", |c| {
        c.iter(|| {
            black_box(
                serde_json::to_string(
                    &keypair_pw
                        .generate_login_request(UnixSeconds(0), UnixSeconds(0))
                        .unwrap(),
                )
                .unwrap(),
            )
        })
    });
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
