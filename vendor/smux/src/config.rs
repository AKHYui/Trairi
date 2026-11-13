use crate::error::{Result, SmuxError};
use std::time::Duration;

/// Configuration for a smux session.
///
/// `Config` contains all the tunable parameters for a smux session, including
/// keep-alive settings, buffer sizes, and protocol version.
///
/// # Examples
///
/// ## Using default configuration
///
/// ```rust
/// use smux::Config;
///
/// let config = Config::default();
/// assert_eq!(config.version, 1);
/// assert!(config.enable_keep_alive);
/// ```
///
/// ## Creating custom configuration
///
/// ```rust
/// use smux::{Config, ConfigBuilder};
/// use std::time::Duration;
///
/// let config = ConfigBuilder::new()
///     .version(2)
///     .keep_alive_interval(Duration::from_secs(30))
///     .max_frame_size(64 * 1024)
///     .build()
///     .expect("Valid configuration");
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    pub version: u8,
    pub keep_alive_interval: Duration,
    pub keep_alive_timeout: Duration,
    pub max_frame_size: usize,
    pub max_receive_buffer: usize,
    pub max_stream_buffer: usize,
    pub enable_keep_alive: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            keep_alive_interval: Duration::from_secs(10),
            keep_alive_timeout: Duration::from_secs(30),
            max_frame_size: 32 * 1024,           // 32KB
            max_receive_buffer: 4 * 1024 * 1024, // 4MB
            max_stream_buffer: 64 * 1024,        // 64KB
            enable_keep_alive: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.version == 0 {
            return Err(SmuxError::Config("Version cannot be 0".to_string()));
        }

        if self.enable_keep_alive && self.keep_alive_timeout <= self.keep_alive_interval {
            return Err(SmuxError::Config(
                "Keep-alive timeout must be greater than keep-alive interval".to_string(),
            ));
        }

        if self.max_frame_size == 0 {
            return Err(SmuxError::Config("Max frame size cannot be 0".to_string()));
        }

        if self.max_frame_size > 16 * 1024 * 1024 {
            return Err(SmuxError::Config(
                "Max frame size cannot exceed 16MB".to_string(),
            ));
        }

        if self.max_receive_buffer < self.max_frame_size {
            return Err(SmuxError::Config(
                "Max receive buffer must be at least as large as max frame size".to_string(),
            ));
        }

        if self.max_stream_buffer == 0 {
            return Err(SmuxError::Config(
                "Max stream buffer cannot be 0".to_string(),
            ));
        }

        Ok(())
    }
}

/// Builder for creating custom `Config` instances.
///
/// `ConfigBuilder` provides a fluent interface for constructing `Config` objects
/// with custom parameters. It starts with default values and allows selective
/// overriding of specific settings.
///
/// # Examples
///
/// ```rust
/// use smux::ConfigBuilder;
/// use std::time::Duration;
///
/// let config = ConfigBuilder::new()
///     .version(2)
///     .keep_alive_interval(Duration::from_secs(30))
///     .max_frame_size(64 * 1024)
///     .enable_keep_alive(false)
///     .build()
///     .expect("Valid configuration");
/// ```
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: Config::default(),
        }
    }

    pub fn version(mut self, version: u8) -> Self {
        self.config.version = version;
        self
    }

    pub fn keep_alive_interval(mut self, interval: Duration) -> Self {
        self.config.keep_alive_interval = interval;
        self
    }

    pub fn keep_alive_timeout(mut self, timeout: Duration) -> Self {
        self.config.keep_alive_timeout = timeout;
        self
    }

    pub fn max_frame_size(mut self, size: usize) -> Self {
        self.config.max_frame_size = size;
        self
    }

    pub fn max_receive_buffer(mut self, size: usize) -> Self {
        self.config.max_receive_buffer = size;
        self
    }

    pub fn max_stream_buffer(mut self, size: usize) -> Self {
        self.config.max_stream_buffer = size;
        self
    }

    pub fn enable_keep_alive(mut self, enable: bool) -> Self {
        self.config.enable_keep_alive = enable;
        self
    }

    pub fn build(self) -> Result<Config> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_default_config_is_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation() {
        // Test invalid version
        let config = Config {
            version: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Test keep-alive timeout validation
        let config = Config {
            keep_alive_timeout: Duration::from_secs(5),
            keep_alive_interval: Duration::from_secs(10),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Keep-alive disabled should skip validation
        let config = Config {
            keep_alive_timeout: Duration::from_secs(5),
            keep_alive_interval: Duration::from_secs(10),
            enable_keep_alive: false,
            ..Default::default()
        };
        assert!(config.validate().is_ok());

        // Test max frame size validation
        let config = Config {
            max_frame_size: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = Config {
            max_frame_size: 20 * 1024 * 1024,
            ..Default::default()
        }; // 20MB
        assert!(config.validate().is_err());

        // Test receive buffer validation
        let config = Config {
            max_receive_buffer: 1024,
            max_frame_size: 2048,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Test stream buffer validation
        let config = Config {
            max_stream_buffer: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_builder() {
        let config = ConfigBuilder::new()
            .version(2)
            .keep_alive_interval(Duration::from_secs(5))
            .keep_alive_timeout(Duration::from_secs(15))
            .max_frame_size(64 * 1024)
            .max_receive_buffer(8 * 1024 * 1024)
            .max_stream_buffer(128 * 1024)
            .enable_keep_alive(false)
            .build()
            .unwrap();

        assert_eq!(config.version, 2);
        assert_eq!(config.keep_alive_interval, Duration::from_secs(5));
        assert_eq!(config.keep_alive_timeout, Duration::from_secs(15));
        assert_eq!(config.max_frame_size, 64 * 1024);
        assert_eq!(config.max_receive_buffer, 8 * 1024 * 1024);
        assert_eq!(config.max_stream_buffer, 128 * 1024);
        assert!(!config.enable_keep_alive);
    }

    #[test]
    fn test_config_builder_validation_failure() {
        let result = ConfigBuilder::new().version(0).build();

        assert!(result.is_err());
    }

    #[test]
    fn test_keep_alive_validation_when_disabled() {
        let config = ConfigBuilder::new()
            .keep_alive_interval(Duration::from_secs(20))
            .keep_alive_timeout(Duration::from_secs(10))
            .enable_keep_alive(false)
            .build();

        assert!(config.is_ok());
    }
}
