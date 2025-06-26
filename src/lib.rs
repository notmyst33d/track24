// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Myst33d <myst33d@gmail.com>

pub mod error;

use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine, prelude::BASE64_STANDARD};
use md5::{Digest, Md5};
use reqwest::Url;
use serde::{Deserialize, Serialize};

pub use crate::error::{DecryptError, TrackError};

const API_KEY: &str = "084c973bbc1e2a5b0393a44339e97e34";
const SECRET_KEY: &str = "a35c75c236f2fa03be1a3fa5fa91fd05";
const APPLICATION: &str = "net.track24.android.1.123";

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub struct Client {
    client: reqwest::Client,
    security_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ApiResult {
    Ok { status: String, data: String },
    Err { status: String, message: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub id: String,
    pub operation_date_time: String,
    pub operation_attribute: String,
    pub operation_place_name: String,
    pub service_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrackResponseInner {
    pub events: Vec<Event>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrackResponse {
    pub data: TrackResponseInner,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            security_key: None,
        }
    }

    pub async fn track(&mut self, track_number: &str) -> Result<TrackResponse, TrackError> {
        if self.security_key.is_none() {
            match self.send("/android/security.key.php", &[]).await? {
                ApiResult::Ok { data, .. } => {
                    self.security_key = Some(self.decrypt(&data, SECRET_KEY)?)
                }
                ApiResult::Err { message, .. } => return Err(TrackError::ApiError(message)),
            };
        }

        let data = match self
            .send(
                "/tracking.json.php",
                &[("code", track_number), ("type", "update")],
            )
            .await?
        {
            ApiResult::Ok { data, .. } => {
                self.decrypt(&data, self.security_key.as_ref().unwrap())?
            }
            ApiResult::Err { message, .. } => return Err(TrackError::ApiError(message)),
        };

        Ok(serde_json::from_str(&data)?)
    }

    async fn send(&self, path: &str, req: &[(&str, &str)]) -> Result<ApiResult, reqwest::Error> {
        let mut query = vec![("apiKey", API_KEY), ("application", APPLICATION)];
        if let Some(security_key) = &self.security_key {
            query.push(("securityKey", security_key));
        }
        query.extend_from_slice(req);
        let url = Url::parse("https://api.track24.ru").unwrap();
        self.client
            .get(url.join(path).unwrap())
            .query(&query)
            .send()
            .await?
            .json()
            .await
    }

    fn decrypt(&self, ciphertext: &str, key: &str) -> Result<String, DecryptError> {
        let aes_key = {
            let mut hash = Md5::new();
            hash.update(key);
            hash.finalize()
        };

        let aes_iv = {
            let mut hash = Md5::new();
            hash.update("################");
            hash.finalize()
        };

        let mut data = BASE64_STANDARD.decode(ciphertext)?;
        Ok(String::from_utf8(
            Aes128CbcDec::new(&aes_key, &aes_iv)
                .decrypt_padded_mut::<Pkcs7>(&mut data)?
                .to_vec(),
        )?)
    }
}

#[cfg(test)]
mod test {
    use crate::Client;

    #[tokio::test]
    async fn track() {
        let mut client = Client::new();
        client
            .track(&std::env::var("TRACK_NUMBER").unwrap())
            .await
            .unwrap();
    }
}
