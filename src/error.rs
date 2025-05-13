use aes::cipher::block_padding::UnpadError;
use std::string::FromUtf8Error;

macro_rules! transparent_from_error {
    ($into:ty, $from:ty) => {
        impl From<$from> for $into {
            fn from(value: $from) -> Self {
                <$from>::from(value).into()
            }
        }
    };
}

#[derive(thiserror::Error, Debug)]
pub enum BodyDecodingError {
    #[error(transparent)]
    Utf8Error(#[from] FromUtf8Error),

    #[error(transparent)]
    JsonDecodingError(#[from] serde_json::Error),

    #[error(transparent)]
    Base64DecodingError(#[from] base64::DecodeError),

    #[error("{}", .0)]
    DecryptionError(UnpadError),
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    RequestError(#[from] reqwest::Error),

    #[error(transparent)]
    BodyDecodingError(#[from] BodyDecodingError),

    #[error("{}", .0)]
    ApiError(String),
}

transparent_from_error!(Error, FromUtf8Error);
transparent_from_error!(Error, serde_json::Error);
transparent_from_error!(Error, base64::DecodeError);
transparent_from_error!(Error, UnpadError);
