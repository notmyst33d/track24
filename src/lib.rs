pub mod error;

use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine, prelude::BASE64_STANDARD};
use md5::{Digest, Md5};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::error::Error;

const API_KEY: &'static str = "7255df155458b210b2a13a27cc1c0546";
const SECRET_KEY: &'static str = "c931242c09483332c56f2a7480a3a226";
const APPLICATION: &'static str = "net.track24.android.1.118";

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

impl Client {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            security_key: None,
        }
    }

    pub async fn track(&mut self, track_number: &str) -> Result<TrackResponse, Error> {
        if self.security_key.is_none() {
            match self.send("/android/security.key.php", &[]).await? {
                ApiResult::Ok { data, .. } => {
                    self.security_key = Some(self.decrypt(&data, SECRET_KEY)?)
                }
                ApiResult::Err { message, .. } => return Err(Error::ApiError(message)),
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
                self.decrypt(&data, &self.security_key.as_ref().unwrap())?
            }
            ApiResult::Err { message, .. } => return Err(Error::ApiError(message)),
        };

        Ok(serde_json::from_str(&data)?)
    }

    async fn send(&self, path: &str, req: &[(&str, &str)]) -> Result<ApiResult, Error> {
        let mut query = vec![("apiKey", API_KEY), ("application", APPLICATION)];
        if let Some(security_key) = &self.security_key {
            query.push(("securityKey", &security_key));
        }
        query.extend_from_slice(req);
        let url = Url::parse("https://api.track24.ru").unwrap();
        Ok(self
            .client
            .get(url.join(path).unwrap())
            .query(&query)
            .send()
            .await?
            .json()
            .await?)
    }

    fn decrypt(&self, ciphertext: &str, key: &str) -> Result<String, Error> {
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
        simple_logger::init().unwrap();
        let mut client = Client::new();
        client
            .track(&std::env::var("TRACK_NUMBER").unwrap())
            .await
            .unwrap();
    }
}
