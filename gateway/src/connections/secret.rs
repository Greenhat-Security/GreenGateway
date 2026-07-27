use std::fmt;

use zeroize::Zeroizing;

pub const MAX_HTTP_CREDENTIAL_BYTES: usize = 8 * 1024;
pub const MAX_TLS_PRIVATE_KEY_BYTES: usize = 256 * 1024;
pub const MAX_TLS_CERTIFICATE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretPurpose {
    HeaderApiKey,
    StaticBearer,
    OAuthClientSecret,
    TlsPrivateKey,
    TlsCertificate,
    TlsCaBundle,
}

impl SecretPurpose {
    const fn max_bytes(self) -> usize {
        match self {
            Self::HeaderApiKey | Self::StaticBearer | Self::OAuthClientSecret => {
                MAX_HTTP_CREDENTIAL_BYTES
            }
            Self::TlsPrivateKey => MAX_TLS_PRIVATE_KEY_BYTES,
            Self::TlsCertificate | Self::TlsCaBundle => MAX_TLS_CERTIFICATE_BYTES,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SecretValueError {
    Empty,
    TooLarge { maximum: usize },
    ContainsNul,
}

/// Resolved secret material that cannot be serialized or accidentally logged.
///
/// The owned bytes are zeroized on replacement and drop. Callers receive only a
/// borrowed view so ordinary credential handling does not create another owned
/// copy.
pub struct ResolvedSecret {
    purpose: SecretPurpose,
    value: Zeroizing<Vec<u8>>,
}

impl ResolvedSecret {
    pub fn new(purpose: SecretPurpose, value: Vec<u8>) -> Result<Self, SecretValueError> {
        let value = Zeroizing::new(value);
        if value.is_empty() {
            return Err(SecretValueError::Empty);
        }
        if value.len() > purpose.max_bytes() {
            return Err(SecretValueError::TooLarge {
                maximum: purpose.max_bytes(),
            });
        }
        if value.contains(&0) {
            return Err(SecretValueError::ContainsNul);
        }

        Ok(Self { purpose, value })
    }

    pub fn purpose(&self) -> SecretPurpose {
        self.purpose
    }

    pub fn expose(&self) -> &[u8] {
        self.value.as_slice()
    }

    pub fn replace(&mut self, value: Vec<u8>) -> Result<(), SecretValueError> {
        let replacement = Self::new(self.purpose, value)?;
        self.value = replacement.value;
        Ok(())
    }
}

impl fmt::Debug for ResolvedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &[u8] = b"greengateway-secret-canary";

    #[test]
    fn debug_never_exposes_secret_material() {
        let secret = ResolvedSecret::new(SecretPurpose::StaticBearer, CANARY.to_vec())
            .expect("bounded canary should be accepted");

        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert!(!format!("{secret:?}").contains("canary"));
    }

    #[test]
    fn values_are_not_trimmed_or_transformed() {
        let value = b"  exact credential bytes  ".to_vec();
        let secret = ResolvedSecret::new(SecretPurpose::HeaderApiKey, value.clone())
            .expect("bounded value should be accepted");

        assert_eq!(secret.expose(), value);
    }

    #[test]
    fn empty_oversized_and_nul_values_fail_closed() {
        assert_eq!(
            ResolvedSecret::new(SecretPurpose::StaticBearer, Vec::new())
                .expect_err("empty secret must fail"),
            SecretValueError::Empty
        );
        assert_eq!(
            ResolvedSecret::new(
                SecretPurpose::OAuthClientSecret,
                vec![b'x'; MAX_HTTP_CREDENTIAL_BYTES + 1]
            )
            .expect_err("oversized secret must fail"),
            SecretValueError::TooLarge {
                maximum: MAX_HTTP_CREDENTIAL_BYTES
            }
        );
        assert_eq!(
            ResolvedSecret::new(SecretPurpose::TlsPrivateKey, b"key\0material".to_vec())
                .expect_err("NUL-bearing secret must fail"),
            SecretValueError::ContainsNul
        );
    }

    #[test]
    fn failed_replacement_keeps_current_value() {
        let mut secret = ResolvedSecret::new(SecretPurpose::StaticBearer, CANARY.to_vec())
            .expect("bounded canary should be accepted");

        assert_eq!(
            secret
                .replace(Vec::new())
                .expect_err("invalid replacement must fail"),
            SecretValueError::Empty
        );
        assert_eq!(secret.expose(), CANARY);
    }
}
