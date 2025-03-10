use nullnet_libtoken::Token;
use std::time::{SystemTime, UNIX_EPOCH};

const EXPIRATION_MARGIN: u64 = 60 * 5;

#[derive(Debug)]
pub(crate) struct TokenWrapper {
    pub jwt: String,
    pub info: Token,
}

impl TokenWrapper {
    pub(crate) fn from_jwt(jwt: String) -> Result<Self, String> {
        let info = Token::from_jwt(&jwt)?;
        Ok(Self { jwt, info })
    }

    pub(crate) fn is_expired(&self) -> bool {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.info.exp <= (timestamp - EXPIRATION_MARGIN)
    }
}
