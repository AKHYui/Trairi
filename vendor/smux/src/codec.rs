use crate::{
    command::Command,
    config::Config,
    error::{Result, SmuxError},
    frame::{Frame, HEADER_SIZE},
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone)]
pub struct Codec {
    config: Config,
    max_frame_size: usize,
}

impl Codec {
    pub fn new(config: Config) -> Self {
        let max_frame_size = config.max_frame_size;
        Self {
            config,
            max_frame_size,
        }
    }

    fn decode_header(src: &mut BytesMut) -> Result<(u8, Command, u32, u16)> {
        if src.len() < HEADER_SIZE {
            return Err(SmuxError::InsufficientData);
        }

        let version = src.get_u8();
        let cmd_byte = src.get_u8();
        let length = src.get_u16_le();
        let stream_id = src.get_u32_le();

        let cmd = Command::from_byte(cmd_byte)?;

        Ok((version, cmd, stream_id, length))
    }

    fn encode_header(dst: &mut BytesMut, version: u8, cmd: Command, stream_id: u32, length: u16) {
        dst.put_u8(version);
        dst.put_u8(cmd.to_byte());
        dst.put_u16_le(length);
        dst.put_u32_le(stream_id);
    }

    fn decode_upd_data(data: &[u8]) -> Result<(u32, u32)> {
        if data.len() != 8 {
            return Err(SmuxError::ProtocolViolation(
                "UPD frame must have exactly 8 bytes of data".to_string(),
            ));
        }

        let mut buf = data;
        let consumed = buf.get_u32_le();
        let window = buf.get_u32_le();

        Ok((consumed, window))
    }

    fn encode_upd_data(consumed: u32, window: u32) -> Bytes {
        let mut buf = BytesMut::with_capacity(8);
        buf.put_u32_le(consumed);
        buf.put_u32_le(window);
        buf.freeze()
    }
}

impl Decoder for Codec {
    type Item = Frame;
    type Error = SmuxError;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        // Check if we have enough bytes for the header
        if src.len() < HEADER_SIZE {
            return Ok(None);
        }

        // Peek at the header without consuming the bytes
        let mut peek_buf = src.clone();
        let (version, _cmd, _stream_id, length) = Self::decode_header(&mut peek_buf)?;

        // Check for oversized frames
        let total_frame_size = HEADER_SIZE + length as usize;
        if total_frame_size > self.max_frame_size {
            return Err(SmuxError::FrameTooLarge {
                size: total_frame_size,
                max: self.max_frame_size,
            });
        }

        // Check if we have the complete frame
        if src.len() < total_frame_size {
            // Reserve space for the full frame
            src.reserve(total_frame_size - src.len());
            return Ok(None);
        }

        // Now we can safely consume the bytes
        let (_version, cmd, stream_id, length) = Self::decode_header(src)?;

        // Read the data payload
        let data_bytes = src.split_to(length as usize);
        let data = data_bytes.freeze();

        // Handle UPD command special case for v2
        let final_cmd = match cmd {
            Command::Upd { .. } if version >= 2 => {
                let (consumed, window) = Self::decode_upd_data(&data)?;
                Command::Upd { consumed, window }
            }
            _ => cmd,
        };

        // Create the frame
        let frame_data = match final_cmd {
            Command::Upd { .. } => Bytes::new(), // UPD frames don't carry user data
            _ => data,
        };

        let frame = Frame::new(version, final_cmd, stream_id, frame_data);

        // Validate the frame
        frame.validate(&self.config)?;

        Ok(Some(frame))
    }
}

impl Encoder<Frame> for Codec {
    type Error = SmuxError;

    fn encode(&mut self, frame: Frame, dst: &mut BytesMut) -> std::result::Result<(), Self::Error> {
        // Validate the frame first
        frame.validate(&self.config)?;

        // Determine the data to encode
        let (data_to_encode, length) = match frame.cmd {
            Command::Upd { consumed, window } if frame.version >= 2 => {
                let upd_data = Self::encode_upd_data(consumed, window);
                let len = upd_data.len() as u16;
                (upd_data, len)
            }
            _ => {
                let len = frame.data.len() as u16;
                (frame.data.clone(), len)
            }
        };

        // Check total frame size
        let total_size = HEADER_SIZE + length as usize;
        if total_size > self.max_frame_size {
            return Err(SmuxError::FrameTooLarge {
                size: total_size,
                max: self.max_frame_size,
            });
        }

        // Reserve space
        dst.reserve(total_size);

        // Encode header
        Self::encode_header(dst, frame.version, frame.cmd, frame.stream_id, length);

        // Encode data
        dst.put_slice(&data_to_encode);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    fn test_config() -> Config {
        Config::default()
    }

    #[test]
    fn test_codec_round_trip_syn() {
        let mut codec = Codec::new(test_config());
        let frame = Frame::new_syn(1, 123);

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_codec_round_trip_fin() {
        let mut codec = Codec::new(test_config());
        let frame = Frame::new_fin(1, 123);

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_codec_round_trip_psh() {
        let mut codec = Codec::new(test_config());
        let data = Bytes::from("hello world");
        let frame = Frame::new_psh(1, 123, data);

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_codec_round_trip_nop() {
        let mut codec = Codec::new(test_config());
        let frame = Frame::new_nop(1);

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_codec_round_trip_upd() {
        let mut codec = Codec::new(test_config());
        let frame = Frame::new_upd(2, 123, 100, 200);

        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn test_decode_partial_header() {
        let mut codec = Codec::new(test_config());
        let frame = Frame::new_syn(1, 123);

        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        // Try to decode with partial header
        let mut partial = BytesMut::from(&buf[..4]);
        let result = codec.decode(&mut partial).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_decode_partial_data() {
        let mut codec = Codec::new(test_config());
        let data = Bytes::from("hello world");
        let frame = Frame::new_psh(1, 123, data);

        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        // Try to decode with incomplete data
        let mut partial = BytesMut::from(&buf[..HEADER_SIZE + 5]);
        let result = codec.decode(&mut partial).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_decode_multiple_frames() {
        let mut codec = Codec::new(test_config());
        let frame1 = Frame::new_syn(1, 123);
        let frame2 = Frame::new_fin(1, 456);

        let mut buf = BytesMut::new();
        codec.encode(frame1.clone(), &mut buf).unwrap();
        codec.encode(frame2.clone(), &mut buf).unwrap();

        let decoded1 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame1, decoded1);

        let decoded2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame2, decoded2);

        // Buffer should be empty now
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn test_decode_oversized_frame() {
        let config = Config {
            max_frame_size: 100,
            ..Default::default()
        };
        let mut codec = Codec::new(config);

        // Create a frame that's too large
        let large_data = Bytes::from(vec![0u8; 200]);
        let frame = Frame::new_psh(1, 123, large_data);

        let mut buf = BytesMut::new();
        // This should fail during encoding
        assert!(codec.encode(frame, &mut buf).is_err());
    }

    #[test]
    fn test_decode_invalid_protocol_version() {
        let mut codec = Codec::new(test_config());

        // Manually create a buffer with invalid version
        let mut buf = BytesMut::new();
        buf.put_u8(0); // Invalid version
        buf.put_u8(Command::SYN); // Command
        buf.put_u16_le(0); // Length
        buf.put_u32_le(123); // Stream ID

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_invalid_command() {
        let mut codec = Codec::new(test_config());

        // Manually create a buffer with invalid command
        let mut buf = BytesMut::new();
        buf.put_u8(1); // Version
        buf.put_u8(255); // Invalid command
        buf.put_u16_le(0); // Length
        buf.put_u32_le(123); // Stream ID

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_upd_frame_encoding() {
        let mut codec = Codec::new(test_config());
        let frame = Frame::new_upd(2, 123, 100, 200);

        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        // Check the encoded format
        assert_eq!(buf.len(), HEADER_SIZE + 8); // Header + 8 bytes for consumed/window

        // Verify header
        assert_eq!(buf[0], 2); // Version
        assert_eq!(buf[1], Command::UPD); // Command
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 8); // Length
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 123); // Stream ID

        // Verify UPD data
        let consumed = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let window = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        assert_eq!(consumed, 100);
        assert_eq!(window, 200);
    }

    #[test]
    fn test_invalid_upd_data_length() {
        let mut codec = Codec::new(test_config());

        // Manually create UPD frame with wrong data length
        let mut buf = BytesMut::new();
        buf.put_u8(2); // Version
        buf.put_u8(Command::UPD); // Command
        buf.put_u16_le(4); // Wrong length (should be 8)
        buf.put_u32_le(123); // Stream ID
        buf.put_u32_le(100); // Only 4 bytes instead of 8

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }
}
