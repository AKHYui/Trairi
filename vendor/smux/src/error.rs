use std::io;
use thiserror::Error;

/// Convenient type alias for `Result<T, SmuxError>`.
pub type Result<T> = std::result::Result<T, SmuxError>;

/// Error types for the smux library.
///
/// `SmuxError` represents all possible error conditions that can occur
/// when using the smux library, from I/O errors to protocol violations.
#[derive(Debug, Error)]
pub enum SmuxError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Invalid protocol version: {0}")]
    InvalidProtocol(u8),

    #[error("Frame too large: {size} bytes (max: {max})")]
    FrameTooLarge { size: usize, max: usize },

    #[error("Session closed")]
    SessionClosed,

    #[error("Stream not found: {0}")]
    StreamNotFound(u32),

    #[error("Stream already exists: {0}")]
    StreamAlreadyExists(u32),

    #[error("Invalid stream ID: {0}")]
    InvalidStreamId(u32),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid frame format")]
    InvalidFrame,

    #[error("Connection timeout")]
    Timeout,

    #[error("Buffer overflow")]
    BufferOverflow,

    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),

    #[error("Insufficient data for frame parsing")]
    InsufficientData,
}

impl SmuxError {
    pub fn is_recoverable(&self) -> bool {
        match self {
            SmuxError::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ),
            SmuxError::Timeout => true,
            SmuxError::BufferOverflow => true,
            SmuxError::SessionClosed
            | SmuxError::InvalidProtocol(_)
            | SmuxError::Config(_)
            | SmuxError::ProtocolViolation(_)
            | SmuxError::InsufficientData => false,
            SmuxError::FrameTooLarge { .. }
            | SmuxError::StreamNotFound(_)
            | SmuxError::StreamAlreadyExists(_)
            | SmuxError::InvalidStreamId(_)
            | SmuxError::InvalidFrame => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error as IoError, ErrorKind};

    #[test]
    fn test_error_display() {
        let err = SmuxError::InvalidProtocol(2);
        assert_eq!(err.to_string(), "Invalid protocol version: 2");

        let err = SmuxError::FrameTooLarge {
            size: 1024,
            max: 512,
        };
        assert_eq!(err.to_string(), "Frame too large: 1024 bytes (max: 512)");

        let err = SmuxError::Config("Invalid setting".to_string());
        assert_eq!(err.to_string(), "Configuration error: Invalid setting");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = IoError::new(ErrorKind::UnexpectedEof, "Connection lost");
        let smux_err: SmuxError = io_err.into();

        match smux_err {
            SmuxError::Io(_) => (),
            _ => panic!("Expected SmuxError::Io"),
        }
    }

    #[test]
    fn test_is_recoverable() {
        // Recoverable errors
        let would_block = SmuxError::Io(IoError::new(ErrorKind::WouldBlock, ""));
        assert!(would_block.is_recoverable());

        let interrupted = SmuxError::Io(IoError::new(ErrorKind::Interrupted, ""));
        assert!(interrupted.is_recoverable());

        let timeout = SmuxError::Timeout;
        assert!(timeout.is_recoverable());

        let buffer_overflow = SmuxError::BufferOverflow;
        assert!(buffer_overflow.is_recoverable());

        // Non-recoverable errors
        let session_closed = SmuxError::SessionClosed;
        assert!(!session_closed.is_recoverable());

        let invalid_protocol = SmuxError::InvalidProtocol(2);
        assert!(!invalid_protocol.is_recoverable());

        let config_err = SmuxError::Config("Invalid".to_string());
        assert!(!config_err.is_recoverable());

        let frame_too_large = SmuxError::FrameTooLarge {
            size: 1024,
            max: 512,
        };
        assert!(!frame_too_large.is_recoverable());

        let other_io_err = SmuxError::Io(IoError::new(ErrorKind::UnexpectedEof, ""));
        assert!(!other_io_err.is_recoverable());
    }
}
