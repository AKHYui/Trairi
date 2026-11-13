use crate::error::{Result, SmuxError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Syn,
    Fin,
    Psh,
    Nop,
    Upd { consumed: u32, window: u32 },
}

impl Command {
    pub const SYN: u8 = 0;
    pub const FIN: u8 = 1;
    pub const PSH: u8 = 2;
    pub const NOP: u8 = 3;
    pub const UPD: u8 = 4;

    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            Self::SYN => Ok(Command::Syn),
            Self::FIN => Ok(Command::Fin),
            Self::PSH => Ok(Command::Psh),
            Self::NOP => Ok(Command::Nop),
            Self::UPD => Ok(Command::Upd {
                consumed: 0,
                window: 0,
            }),
            _ => Err(SmuxError::InvalidFrame),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            Command::Syn => Self::SYN,
            Command::Fin => Self::FIN,
            Command::Psh => Self::PSH,
            Command::Nop => Self::NOP,
            Command::Upd { .. } => Self::UPD,
        }
    }

    pub fn is_control(self) -> bool {
        matches!(
            self,
            Command::Syn | Command::Fin | Command::Nop | Command::Upd { .. }
        )
    }

    #[allow(dead_code)]
    pub fn can_carry_data(self) -> bool {
        matches!(self, Command::Psh)
    }

    pub fn requires_v2(self) -> bool {
        matches!(self, Command::Upd { .. })
    }

    #[allow(dead_code)]
    pub fn consumed(self) -> Option<u32> {
        match self {
            Command::Upd { consumed, .. } => Some(consumed),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn window(self) -> Option<u32> {
        match self {
            Command::Upd { window, .. } => Some(window),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_byte_conversion() {
        let commands = [
            Command::Syn,
            Command::Fin,
            Command::Psh,
            Command::Nop,
            Command::Upd {
                consumed: 100,
                window: 200,
            },
        ];

        for cmd in commands {
            let byte = cmd.to_byte();
            let restored = Command::from_byte(byte).unwrap();

            // For UPD commands, we only check the command type since consumed/window
            // are stored separately in the frame header
            match (cmd, restored) {
                (Command::Upd { .. }, Command::Upd { .. }) => (),
                (a, b) => assert_eq!(a, b),
            }
        }
    }

    #[test]
    fn test_invalid_command_byte() {
        assert!(Command::from_byte(255).is_err());
        assert!(Command::from_byte(5).is_err());
    }

    #[test]
    fn test_command_properties() {
        // Control commands
        assert!(Command::Syn.is_control());
        assert!(Command::Fin.is_control());
        assert!(Command::Nop.is_control());
        assert!(
            Command::Upd {
                consumed: 0,
                window: 0
            }
            .is_control()
        );

        // Non-control command
        assert!(!Command::Psh.is_control());

        // Data carrying capability
        assert!(Command::Psh.can_carry_data());
        assert!(!Command::Syn.can_carry_data());
        assert!(!Command::Fin.can_carry_data());
        assert!(!Command::Nop.can_carry_data());
        assert!(
            !Command::Upd {
                consumed: 0,
                window: 0
            }
            .can_carry_data()
        );

        // Version 2 requirements
        assert!(
            Command::Upd {
                consumed: 0,
                window: 0
            }
            .requires_v2()
        );
        assert!(!Command::Syn.requires_v2());
        assert!(!Command::Fin.requires_v2());
        assert!(!Command::Psh.requires_v2());
        assert!(!Command::Nop.requires_v2());
    }

    #[test]
    fn test_upd_command_values() {
        let cmd = Command::Upd {
            consumed: 123,
            window: 456,
        };
        assert_eq!(cmd.consumed(), Some(123));
        assert_eq!(cmd.window(), Some(456));

        assert_eq!(Command::Syn.consumed(), None);
        assert_eq!(Command::Syn.window(), None);
    }
}
