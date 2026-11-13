use crate::{
    command::Command,
    config::Config,
    error::{Result, SmuxError},
};
use bytes::Bytes;

pub const HEADER_SIZE: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: u8,
    pub cmd: Command,
    pub stream_id: u32,
    pub data: Bytes,
}

impl Frame {
    pub fn new(version: u8, cmd: Command, stream_id: u32, data: Bytes) -> Self {
        Self {
            version,
            cmd,
            stream_id,
            data,
        }
    }

    pub fn new_syn(version: u8, stream_id: u32) -> Self {
        Self::new(version, Command::Syn, stream_id, Bytes::new())
    }

    pub fn new_fin(version: u8, stream_id: u32) -> Self {
        Self::new(version, Command::Fin, stream_id, Bytes::new())
    }

    pub fn new_psh(version: u8, stream_id: u32, data: Bytes) -> Self {
        Self::new(version, Command::Psh, stream_id, data)
    }

    pub fn new_nop(version: u8) -> Self {
        Self::new(version, Command::Nop, 0, Bytes::new())
    }

    #[allow(dead_code)]
    pub fn new_upd(version: u8, stream_id: u32, consumed: u32, window: u32) -> Self {
        Self::new(
            version,
            Command::Upd { consumed, window },
            stream_id,
            Bytes::new(),
        )
    }

    pub fn total_size(&self) -> usize {
        HEADER_SIZE + self.data.len()
    }

    #[allow(dead_code)]
    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        // Check protocol version
        if self.version == 0 {
            return Err(SmuxError::InvalidProtocol(self.version));
        }

        // Check if command requires v2 but we're using v1
        if self.cmd.requires_v2() && self.version < 2 {
            return Err(SmuxError::ProtocolViolation(
                "UPD command requires protocol version 2".to_string(),
            ));
        }

        // Check frame size
        if self.total_size() > config.max_frame_size {
            return Err(SmuxError::FrameTooLarge {
                size: self.total_size(),
                max: config.max_frame_size,
            });
        }

        // Control frames should not carry data
        if self.cmd.is_control() && !self.data.is_empty() {
            return Err(SmuxError::ProtocolViolation(
                "Control frames cannot carry data".to_string(),
            ));
        }

        // Stream ID validation
        self.validate_stream_id()?;

        Ok(())
    }

    fn validate_stream_id(&self) -> Result<()> {
        match self.cmd {
            Command::Nop => {
                // NOP frames should use stream ID 0
                if self.stream_id != 0 {
                    return Err(SmuxError::InvalidStreamId(self.stream_id));
                }
            }
            _ => {
                // Other frames must have non-zero stream ID
                if self.stream_id == 0 {
                    return Err(SmuxError::InvalidStreamId(self.stream_id));
                }
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn consumed(&self) -> Option<u32> {
        self.cmd.consumed()
    }

    #[allow(dead_code)]
    pub fn window(&self) -> Option<u32> {
        self.cmd.window()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    #[test]
    fn test_frame_creation() {
        let data = Bytes::from("hello");
        let frame = Frame::new(1, Command::Psh, 123, data.clone());

        assert_eq!(frame.version, 1);
        assert_eq!(frame.cmd, Command::Psh);
        assert_eq!(frame.stream_id, 123);
        assert_eq!(frame.data, data);
    }

    #[test]
    fn test_frame_constructors() {
        let syn_frame = Frame::new_syn(1, 123);
        assert_eq!(syn_frame.cmd, Command::Syn);
        assert_eq!(syn_frame.stream_id, 123);
        assert!(syn_frame.data.is_empty());

        let fin_frame = Frame::new_fin(1, 123);
        assert_eq!(fin_frame.cmd, Command::Fin);
        assert_eq!(fin_frame.stream_id, 123);
        assert!(fin_frame.data.is_empty());

        let data = Bytes::from("test");
        let psh_frame = Frame::new_psh(1, 123, data.clone());
        assert_eq!(psh_frame.cmd, Command::Psh);
        assert_eq!(psh_frame.stream_id, 123);
        assert_eq!(psh_frame.data, data);

        let nop_frame = Frame::new_nop(1);
        assert_eq!(nop_frame.cmd, Command::Nop);
        assert_eq!(nop_frame.stream_id, 0);
        assert!(nop_frame.data.is_empty());

        let upd_frame = Frame::new_upd(2, 123, 100, 200);
        assert_eq!(
            upd_frame.cmd,
            Command::Upd {
                consumed: 100,
                window: 200
            }
        );
        assert_eq!(upd_frame.stream_id, 123);
        assert!(upd_frame.data.is_empty());
    }

    #[test]
    fn test_frame_size_calculation() {
        let empty_frame = Frame::new_syn(1, 123);
        assert_eq!(empty_frame.total_size(), HEADER_SIZE);
        assert_eq!(empty_frame.data_len(), 0);
        assert!(empty_frame.is_empty());

        let data = Bytes::from("hello");
        let data_frame = Frame::new_psh(1, 123, data);
        assert_eq!(data_frame.total_size(), HEADER_SIZE + 5);
        assert_eq!(data_frame.data_len(), 5);
        assert!(!data_frame.is_empty());
    }

    #[test]
    fn test_frame_validation() {
        let config = Config::default();

        // Valid frames
        let syn_frame = Frame::new_syn(1, 123);
        assert!(syn_frame.validate(&config).is_ok());

        let psh_frame = Frame::new_psh(1, 123, Bytes::from("data"));
        assert!(psh_frame.validate(&config).is_ok());

        let nop_frame = Frame::new_nop(1);
        assert!(nop_frame.validate(&config).is_ok());

        // Invalid protocol version
        let invalid_version = Frame::new(0, Command::Syn, 123, Bytes::new());
        assert!(invalid_version.validate(&config).is_err());

        // UPD command with v1 protocol
        let upd_v1 = Frame::new_upd(1, 123, 100, 200);
        assert!(upd_v1.validate(&config).is_err());

        // UPD command with v2 protocol should be valid
        let upd_v2 = Frame::new_upd(2, 123, 100, 200);
        assert!(upd_v2.validate(&config).is_ok());
    }

    #[test]
    fn test_frame_size_validation() {
        let config = Config {
            max_frame_size: 100,
            ..Default::default()
        };

        // Frame that's too large
        let large_data = Bytes::from(vec![0u8; 200]);
        let large_frame = Frame::new_psh(1, 123, large_data);
        assert!(large_frame.validate(&config).is_err());

        // Frame that fits
        let small_data = Bytes::from(vec![0u8; 50]);
        let small_frame = Frame::new_psh(1, 123, small_data);
        assert!(small_frame.validate(&config).is_ok());
    }

    #[test]
    fn test_control_frames_with_data() {
        let config = Config::default();
        let data = Bytes::from("invalid");

        // Control frames should not carry data
        let syn_with_data = Frame::new(1, Command::Syn, 123, data.clone());
        assert!(syn_with_data.validate(&config).is_err());

        let fin_with_data = Frame::new(1, Command::Fin, 123, data.clone());
        assert!(fin_with_data.validate(&config).is_err());

        let nop_with_data = Frame::new(1, Command::Nop, 0, data.clone());
        assert!(nop_with_data.validate(&config).is_err());

        let upd_with_data = Frame::new(
            2,
            Command::Upd {
                consumed: 0,
                window: 0,
            },
            123,
            data,
        );
        assert!(upd_with_data.validate(&config).is_err());
    }

    #[test]
    fn test_stream_id_validation() {
        let config = Config::default();

        // NOP frame with non-zero stream ID
        let invalid_nop = Frame::new(1, Command::Nop, 123, Bytes::new());
        assert!(invalid_nop.validate(&config).is_err());

        // Non-NOP frame with zero stream ID
        let invalid_syn = Frame::new(1, Command::Syn, 0, Bytes::new());
        assert!(invalid_syn.validate(&config).is_err());

        let invalid_psh = Frame::new(1, Command::Psh, 0, Bytes::from("data"));
        assert!(invalid_psh.validate(&config).is_err());
    }

    #[test]
    fn test_upd_frame_values() {
        let upd_frame = Frame::new_upd(2, 123, 100, 200);
        assert_eq!(upd_frame.consumed(), Some(100));
        assert_eq!(upd_frame.window(), Some(200));

        let syn_frame = Frame::new_syn(1, 123);
        assert_eq!(syn_frame.consumed(), None);
        assert_eq!(syn_frame.window(), None);
    }
}
