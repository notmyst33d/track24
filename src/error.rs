// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Myst33d <myst33d@gmail.com>

use std::string::FromUtf8Error;

use aes::cipher::block_padding::UnpadError;
use base64::DecodeError;

macro_rules! from {
    ($from:ty, $error:ty, $variant:expr) => {
        impl From<$from> for $error {
            fn from(_: $from) -> Self {
                $variant
            }
        }
    };
}

#[derive(thiserror::Error, Debug)]
#[error("data decryption failed")]
pub enum DecryptError {
    #[error("invalid padding")]
    InvalidPadding,

    #[error("invalid utf-8")]
    InvalidUtf8,

    #[error("invalid base64")]
    InvalidBase64,
}

#[derive(thiserror::Error, Debug)]
#[error("failed to send track request")]
pub enum TrackError {
    #[error(transparent)]
    SendError(#[from] reqwest::Error),

    #[error(transparent)]
    DecryptError(#[from] DecryptError),

    #[error(transparent)]
    DeserializationError(#[from] serde_json::Error),

    #[error("api returned an error: {0}")]
    ApiError(String),
}

from!(UnpadError, DecryptError, DecryptError::InvalidPadding);
from!(FromUtf8Error, DecryptError, DecryptError::InvalidUtf8);
from!(DecodeError, DecryptError, DecryptError::InvalidBase64);
