use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use std::{
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use tokio::{task::JoinHandle, time::sleep};
use tracing::*;

use crate::structs::{JwkConfiguration, JwkKeys, KeyResponse, PublicKeysError};

const JWK_URL: &str =
    "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

pub fn get_configuration(project_id: &str) -> JwkConfiguration {
    JwkConfiguration {
        jwk_url: JWK_URL.to_owned(),
        audience: project_id.to_owned(),
        issuer: format!("https://securetoken.google.com/{}", project_id),
    }
}

fn parse_max_age_value(cache_control_value: &str) -> Result<Duration, PublicKeysError> {
    let tokens: Vec<(&str, &str)> = cache_control_value
        .split(',')
        .map(|s| s.split('=').map(|ss| ss.trim()).collect::<Vec<&str>>())
        .map(|ss| {
            let key = ss.first().unwrap_or(&"");
            let val = ss.get(1).unwrap_or(&"");
            (*key, *val)
        })
        .collect();
    match tokens
        .iter()
        .find(|(key, _)| key.to_lowercase() == *"max-age")
    {
        None => Err(PublicKeysError::NoMaxAgeSpecified),
        Some((_, str_val)) => Ok(Duration::from_secs(
            str_val
                .parse()
                .map_err(|_| PublicKeysError::NonNumericMaxAge)?,
        )),
    }
}

async fn get_public_keys(fallback_timeout: &Duration) -> Result<JwkKeys, PublicKeysError> {
    let response = reqwest::get(JWK_URL)
        .await
        .map_err(PublicKeysError::CouldntFetchPublicKeys)?;

    let cache_control = match response.headers().get("Cache-Control") {
        Some(header_value) => header_value.to_str(),
        None => return Err(PublicKeysError::NoCacheControlHeader),
    };

    let max_age = match cache_control {
        Ok(v) => parse_max_age_value(v),
        Err(_) => return Err(PublicKeysError::MaxAgeValueEmpty),
    };

    let public_keys = response
        .json::<KeyResponse>()
        .await
        .map_err(|e| {
            PublicKeysError::CannotParsePublicKey(e)
        })?;

    Ok(JwkKeys {
        keys: public_keys.keys,
        max_age: max_age.unwrap_or(fallback_timeout.clone()),
    })
}

#[derive(Debug)]
pub enum VerificationError {
    InvalidSignature,
    InvalidKeyAlgorithm,
    InvalidToken,
    NoKidHeader,
    NotfoundMatchKid,
    CannotDecodePublicKeys,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

fn extract_claims_from_unsigned_token<T: DeserializeOwned>(token: &str) ->  Result<T, VerificationError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(VerificationError::InvalidToken);
    }
    let decoded_payload = BASE64_STANDARD_NO_PAD.decode(parts[1].trim()).unwrap();
    let claims: T = serde_json::from_slice(&decoded_payload).map_err(|_| VerificationError::InvalidToken)?;
    Ok(claims)
}

fn verify_id_token_with_project_id<T: DeserializeOwned>(
    config: &JwkConfiguration,
    public_keys: &JwkKeys,
    token: &str,
    allow_unsigned_tokens: bool
) -> Result<T, VerificationError> {
    if allow_unsigned_tokens {
        return extract_claims_from_unsigned_token(token);
    }
    
    let header = decode_header(token).map_err(|_| VerificationError::InvalidSignature)?;

    if header.alg != Algorithm::RS256 {
        return Err(VerificationError::InvalidKeyAlgorithm);
    }

    let kid = match header.kid {
        Some(v) => v,
        None => return Err(VerificationError::NoKidHeader),
    };

    let public_key = match public_keys.keys.iter().find(|v| v.kid == kid) {
        Some(v) => v,
        None => return Err(VerificationError::NotfoundMatchKid),
    };

    let decoding_key = DecodingKey::from_rsa_components(&public_key.n, &public_key.e)
        .map_err(|_| VerificationError::CannotDecodePublicKeys)?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[config.audience.to_owned()]);
    validation.set_issuer(&[config.issuer.to_owned()]);

    let user = decode::<T>(token, &decoding_key, &validation)
        .map_err(|_| VerificationError::InvalidToken)?
        .claims;
    Ok(user)
}

#[derive(Debug)]
struct JwkVerifier {
    keys: JwkKeys,
    config: JwkConfiguration,
}

impl JwkVerifier {
    fn new(project_id: &str, keys: JwkKeys) -> JwkVerifier {
        JwkVerifier {
            keys,
            config: get_configuration(project_id),
        }
    }

    fn verify<T: DeserializeOwned>(&self, token: &str, allow_unsigned_tokens: bool) -> Result<T, VerificationError> {
        verify_id_token_with_project_id(&self.config, &self.keys, token, allow_unsigned_tokens)
    }

    fn set_keys(&mut self, keys: JwkKeys) {
        self.keys = keys;
    }
}

pub struct FirebaseAuthBuilder<'a> {
    project_id: &'a str,
    fallback_timeout: Duration,
    allow_unsigned_tokens: bool,
}
impl<'a> FirebaseAuthBuilder<'a> {
    pub fn new(project_id: &'a str) -> FirebaseAuthBuilder<'a> {
        FirebaseAuthBuilder {
            project_id: project_id,
            fallback_timeout: Duration::from_secs(60),
            allow_unsigned_tokens: false,
        }
    }

    pub fn allow_unsigned_tokens(mut self) -> FirebaseAuthBuilder<'a> {
        self.allow_unsigned_tokens = true;
        self
    }

    pub fn with_fallback_timeout(mut self, timeout: Duration) -> FirebaseAuthBuilder<'a> {
        self.fallback_timeout = timeout;
        self
    }

    pub async fn build(self) -> FirebaseAuth {
        let jwk_keys: JwkKeys = match get_public_keys(&self.fallback_timeout).await {
            Ok(keys) => keys,
            Err(e) => {
                eprintln!("Error getting public jwk keys {:?}", e);
                panic!("Unable to get public jwk keys! Cannot verify user tokens! Shutting down...")
            }
        };
        let verifier = Arc::new(RwLock::new(JwkVerifier::new(self.project_id, jwk_keys)));

        let mut instance = FirebaseAuth {
            fallback_timeout: self.fallback_timeout,
            allow_unsigned_tokens: self.allow_unsigned_tokens,
            verifier,
            handler: Arc::new(Mutex::new(Box::new(tokio::spawn(async {})))),
        };

        instance.start_key_update();
        instance
    }
}

/// Provide a service to automatically pull the new google public key based on the Cache-Control
/// header.
/// If there is an error during refreshing, automatically retry indefinitely every 10 seconds.
#[derive(Clone)]
pub struct FirebaseAuth {
    fallback_timeout: Duration,
    allow_unsigned_tokens: bool,
    verifier: Arc<RwLock<JwkVerifier>>,
    handler: Arc<Mutex<Box<JoinHandle<()>>>>,
}

impl Drop for FirebaseAuth {
    fn drop(&mut self) {
        // Stop the update thread when the updater is destructed
        let handler = self.handler.lock().unwrap();
        handler.abort();
    }
}

impl FirebaseAuth {
    pub fn verify<T: DeserializeOwned>(&self, token: &str) -> Result<T, VerificationError> {
        let verifier = self.verifier.read().unwrap();
        verifier.verify(token, self.allow_unsigned_tokens)
    }

    fn start_key_update(&mut self) {
        let verifier_ref = Arc::clone(&self.verifier);

        let fallback_timeout = self.fallback_timeout.clone();
        let task = tokio::spawn(async move {
            loop {
                let delay = match get_public_keys(&fallback_timeout).await {
                    Ok(jwk_keys) => {
                        let mut verifier = verifier_ref.write().unwrap();
                        verifier.set_keys(jwk_keys.clone());
                        debug!(
                            "Updated JWK keys. Next refresh will be in {:?}",
                            jwk_keys.max_age
                        );
                        jwk_keys.max_age
                    }
                    Err(err) => {
                        warn!("Error getting public jwk keys {:?}", err);
                        warn!("Re-try getting public keys in 10 seconds");
                        Duration::from_secs(10)
                    }
                };
                sleep(delay).await;
            }
        });

        let mut handler = self.handler.lock().unwrap();
        *handler = Box::new(task);
    }
}
