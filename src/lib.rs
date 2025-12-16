//! # SnowWT
//! A partial implementation of snowflake authentication patterns.
//!
//! This crate provides building blocks for making your own snowflake authentication
//! in rust.
//!
//! To get started, create a [`LoginCredentials`]

#![no_std]

extern crate alloc;

use alloc::{borrow::Cow, string::String};

use base64::Engine;
use jsonwebtoken::{EncodingKey, Header};
use rsa::{
    pkcs1::EncodeRsaPrivateKey,
    pkcs8::{DecodePrivateKey, spki::EncodePublicKey},
};

pub use rsa;
pub use secrecy;

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretSlice, SecretString};
use sha2::Digest;

/// Arguments for keypair auth.
pub struct KeypairAuth {
    /// optional password for encrypted keys
    pub password: Option<SecretSlice<u8>>,
    /// private key data in pkcs8 pem format
    pub private_key_p8: SecretString,
}

impl KeypairAuth {
    /// Parses the private key from this KeypairAuth
    pub fn private_key(&self) -> Result<rsa::RsaPrivateKey, rsa::pkcs8::Error> {
        match self {
            KeypairAuth {
                password: Some(password),
                private_key_p8,
            } => rsa::RsaPrivateKey::from_pkcs8_encrypted_pem(
                private_key_p8.expose_secret(),
                password.expose_secret(),
            ),
            KeypairAuth {
                password: None,
                private_key_p8,
            } => rsa::RsaPrivateKey::from_pkcs8_pem(private_key_p8.expose_secret()),
        }
    }
}

/// Login authentication method.
pub enum LoginAuth {
    /// Simple password mode
    Password(SecretString),
    /// Keypair auth mode
    Keypair(KeypairAuth),
}

impl LoginAuth {
    /// Constructs a new LoginAuth in password mode
    pub fn password(s: &str) -> Self {
        Self::Password(s.into())
    }
}

/// Top level login credentials that can be used to generate login data.
pub struct LoginCredentials<AccountTy: AsRef<str> = String, UsernameTy: AsRef<str> = String> {
    /// Snowflake account name, can be backed by anything that implements [`AsRef<str>`]
    pub account: AccountTy,
    /// Snowflake username, can be backed by anything that implements [`AsRef<str>`]
    pub username: UsernameTy,
    /// Snowflake authentication method
    pub auth: LoginAuth,
}

/// Simple union construct for serde serialization.
#[derive(serde_derive::Serialize)]
struct SerdeUnion<A, B> {
    /// first part
    #[serde(flatten)]
    a: A,
    /// second part
    #[serde(flatten)]
    b: B,
}

impl<AccountTy: AsRef<str>, UsernameTy: AsRef<str>> LoginCredentials<AccountTy, UsernameTy> {
    /// Constructs a new LoginCredentials with all fields.
    pub fn new(account: AccountTy, username: UsernameTy, auth: LoginAuth) -> Self {
        Self {
            account,
            username,
            auth,
        }
    }

    /// Generates a login request json serializable with extra data injected
    /// into the inner data field.
    ///
    /// # Examples:
    /// ```
    /// # use snowwt::{LoginCredentials, UnixSeconds, LoginAuth};
    /// # use typed_json::json;
    /// let creds = LoginCredentials::new("account", "username", LoginAuth::password("abcde"));
    ///
    /// let serializeable = creds.generate_login_request_with(
    ///     UnixSeconds(0),
    ///     UnixSeconds(0),
    ///     json!{{ "SESSION_PARAMETERS": ["bool"] }},
    /// ).unwrap();
    ///
    /// let s = serde_json::to_string(&serializeable).unwrap();
    ///
    /// assert_eq!(s, serde_json::to_string(&json!{{
    ///     "data": {
    ///         "ACCOUNT_NAME": "account",
    ///         "LOGIN_NAME": "username",
    ///         "AUTHENTICATOR": "SNOWFLAKE",
    ///         "PASSWORD": "abcde",
    ///         "SESSION_PARAMETERS": [ "bool" ],
    ///     }
    /// }}).unwrap());
    /// ```
    pub fn generate_login_request_with<Data: serde::Serialize>(
        &self,
        now: UnixSeconds,
        expire: UnixSeconds,
        with: Data,
    ) -> Result<impl serde::Serialize, Error> {
        let (authenticator, key, value) = match &self.auth {
            LoginAuth::Password(secret_box) => (
                "SNOWFLAKE",
                "PASSWORD",
                Cow::Borrowed(secret_box.expose_secret()),
            ),
            LoginAuth::Keypair(keypair) => {
                let private = keypair.private_key()?;
                // make a secretbox so its cleared on drop
                let mut scratch = SecretBox::default();

                let jwt = generate_jwt(
                    self.account.as_ref(),
                    self.username.as_ref(),
                    &private,
                    now,
                    expire,
                    scratch.expose_secret_mut(),
                )?;

                ("SNOWFLAKE_JWT", "TOKEN", Cow::Owned(jwt))
            }
        };

        let login_request = SerdeUnion {
            a: typed_json::json! {{
                "ACCOUNT_NAME": self.account.as_ref(),
                "LOGIN_NAME": self.username.as_ref(),
                "AUTHENTICATOR": authenticator,
                key: value,
            }},
            b: with,
        };

        Ok(typed_json::json! {{ "data": login_request }})
    }

    /// Generates a login request json serializable.
    ///
    /// # Examples:
    /// ```
    /// # use snowwt::{LoginCredentials, UnixSeconds, LoginAuth};
    /// # use typed_json::json;
    /// let creds = LoginCredentials::new("grey", "beam", LoginAuth::password("duckdb"));
    ///
    /// let serializeable = creds.generate_login_request(
    ///     UnixSeconds(0),
    ///     UnixSeconds(0),
    /// ).unwrap();
    ///
    /// let s = serde_json::to_string(&serializeable).unwrap();
    ///
    /// assert_eq!(s, serde_json::to_string(&json!{{
    ///     "data": {
    ///         "ACCOUNT_NAME": "grey",
    ///         "LOGIN_NAME": "beam",
    ///         "AUTHENTICATOR": "SNOWFLAKE",
    ///         "PASSWORD": "duckdb",
    ///     }
    /// }}).unwrap());
    /// ```
    pub fn generate_login_request(
        &self,
        now: UnixSeconds,
        expire: UnixSeconds,
    ) -> Result<impl serde::Serialize, Error> {
        self.generate_login_request_with(now, expire, ())
    }
}

/// Errors that can arise in snowwt.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// spki encode error
    #[error(transparent)]
    Spki(#[from] rsa::pkcs8::spki::Error),
    /// pkcs8 parse error
    #[error(transparent)]
    Pkcs8(#[from] rsa::pkcs8::Error),
    /// pkcs1 encode error
    #[error(transparent)]
    Pkcs1(#[from] rsa::pkcs1::Error),
    /// jsonwebtoken serialization error
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

/// Typed repr for unix seconds.
#[derive(serde_derive::Serialize)]
#[serde(transparent)]
pub struct UnixSeconds(pub i64);

/// Claims that are used in the JWT auth method.
#[derive(serde_derive::Serialize)]
pub struct JwtClaims<'iss, 'sub> {
    /// expiry time in unix seconds
    pub exp: UnixSeconds,
    /// issuing time in unix seconds
    pub iat: UnixSeconds,
    /// issuing field, contains:
    /// `ACCOUNT.USERNAME.SHA256:PUBKEYHASH`
    pub iss: &'iss str,
    /// subaccount field(?), contains:
    /// `ACCOUNT.USERNAME`
    pub sub: &'sub str,
}

/// A subset of JwtClaims where iss and sub
/// derive from the same allocation.
pub struct IssSub<'a> {
    /// issuing field
    pub iss: &'a str,
    /// subaccount field(?)
    pub sub: &'a str,
}

/// Creates an issuing+sub field from an account, username, pubkey, and scratch space.
///
/// The generation of sub is derived from the generation of iss, borrowing from the same base
/// string, and thus has nearly zero added cost. Because of this, there is no dedicated function
/// to make an iss without also deriving a sub.
pub fn make_iss<'out>(
    account: &str,
    username: &str,
    pubkey: &rsa::RsaPublicKey,
    out: &'out mut String,
) -> Result<IssSub<'out>, Error> {
    const ACCOUNT_USERNAME_SPLIT: &str = ".";
    const SHA256_HEADER: &str = ".SHA256:";
    const SHA256_B64_LEN: usize = 44;

    out.clear();

    out.reserve(
        account.len()
            + username.len()
            + const { ACCOUNT_USERNAME_SPLIT.len() + SHA256_HEADER.len() + SHA256_B64_LEN },
    );

    out.push_str(account);
    out.push_str(ACCOUNT_USERNAME_SPLIT);
    out.push_str(username);

    let sub_offset = out.len();

    out.push_str(SHA256_HEADER);

    let mut cksum = sha2::Sha256::new();

    let pkey = pubkey.to_public_key_der()?;

    cksum.update(pkey.as_bytes());

    base64::engine::general_purpose::STANDARD.encode_string(cksum.finalize(), out);

    Ok(IssSub {
        iss: out.as_str(),
        sub: &out[..sub_offset],
    })
}

/// Generates a login jwt from an account, username, private key, timestamps, and scratch space.
///
/// # Examples
/// ```
/// # use snowwt::{generate_jwt, UnixSeconds, JwtClaims};
/// # use rsa::{
/// #  pkcs1::EncodeRsaPrivateKey,
/// #  pkcs8::{DecodePrivateKey, spki::EncodePublicKey},
/// # };
/// let privkey = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 1024).expect("a");
///
/// let jwt = generate_jwt(
///     "grey", "beam",
///     &privkey,
///     UnixSeconds(0),
///     UnixSeconds(i64::MAX),
///     &mut String::new()
/// ).expect("b");
///
/// #[derive(serde_derive::Deserialize)]
/// struct ParseClaims {
///    iss: String,
///    sub: String,
///    iat: i64,
///    exp: i64,
/// }
///
/// let key = jsonwebtoken::DecodingKey::from_rsa_pem(
///     privkey
///         .to_public_key()
///         .to_public_key_pem(Default::default())
///         .expect("c")
///         .as_bytes()
/// ).expect("e");
///
/// let decoded = jsonwebtoken::decode::<ParseClaims>(
///     jwt,
///     &key,
///     &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256)
/// ).expect("d");
///
/// assert_eq!(decoded.claims.sub, "grey.beam");
/// ```
pub fn generate_jwt(
    account: &str,
    username: &str,
    auth: &rsa::RsaPrivateKey,
    now: UnixSeconds,
    expire: UnixSeconds,
    scratch: &mut String,
) -> Result<String, Error> {
    let IssSub { iss, sub } = make_iss(account, username, &auth.to_public_key(), scratch)?;

    let claim = JwtClaims {
        exp: expire,
        iat: now,
        iss,
        sub,
    };

    let ek = EncodingKey::from_rsa_der(auth.to_pkcs1_der()?.as_bytes());

    let s = jsonwebtoken::encode(&Header::new(jsonwebtoken::Algorithm::RS256), &claim, &ek)?;

    Ok(s)
}
