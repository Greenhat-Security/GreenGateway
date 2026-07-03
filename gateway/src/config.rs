use std::{
    env::{self, VarError},
    error::Error,
    fmt,
    net::SocketAddr,
};

const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen_addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    problems: Vec<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_env_vars(|name| env::var(name))
    }

    fn from_env_vars(
        mut get_var: impl FnMut(&str) -> Result<String, VarError>,
    ) -> Result<Self, ConfigError> {
        let mut problems = Vec::new();

        let listen_addr = parse_socket_addr(
            "LISTEN_ADDR",
            get_var("LISTEN_ADDR"),
            DEFAULT_LISTEN_ADDR,
            &mut problems,
        );

        if problems.is_empty() {
            Ok(Self { listen_addr })
        } else {
            Err(ConfigError { problems })
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "configuration is invalid:")?;
        for problem in &self.problems {
            write!(f, "\n- {problem}")?;
        }
        Ok(())
    }
}

impl Error for ConfigError {}

fn parse_socket_addr(
    name: &str,
    value: Result<String, VarError>,
    default: &str,
    problems: &mut Vec<String>,
) -> SocketAddr {
    let value = match value {
        Ok(value) => value,
        Err(VarError::NotPresent) => default.to_owned(),
        Err(VarError::NotUnicode(value)) => {
            problems.push(format!("{name} must be valid Unicode, got {value:?}"));
            default.to_owned()
        }
    };

    match value.parse() {
        Ok(parsed) => parsed,
        Err(err) => {
            problems.push(format!(
                "{name} must be a valid socket address, got '{value}': {err}"
            ));
            default
                .parse()
                .expect("default listen address should be valid")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_listen_addr_parses() {
        let config = Config::from_env_vars(|name| match name {
            "LISTEN_ADDR" => Ok("127.0.0.1:9090".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect("config should parse");

        assert_eq!(
            config.listen_addr,
            "127.0.0.1:9090"
                .parse::<SocketAddr>()
                .expect("test address should parse")
        );
    }

    #[test]
    fn invalid_listen_addr_is_rejected() {
        let error = Config::from_env_vars(|name| match name {
            "LISTEN_ADDR" => Ok("not-a-socket".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .expect_err("config should reject invalid socket addresses");

        let message = error.to_string();
        assert!(message.contains("configuration is invalid:"));
        assert!(message.contains("LISTEN_ADDR must be a valid socket address"));
        assert!(message.contains("not-a-socket"));
        assert_eq!(error.problems.len(), 1);
    }

    #[test]
    fn missing_listen_addr_uses_default() {
        let config =
            Config::from_env_vars(|_| Err(VarError::NotPresent)).expect("config should parse");

        assert_eq!(
            config.listen_addr,
            DEFAULT_LISTEN_ADDR
                .parse::<SocketAddr>()
                .expect("default address should parse")
        );
    }
}
