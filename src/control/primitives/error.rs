use std::convert::TryFrom;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum TorErrorKind {
    ResourceExhausted,
    SyntaxErrorProtocol,
    UnrecognizedCmd,
    UnimplementedCmd,
    SyntaxErrorCmdArg,
    UnrecognizedCmdArg,
    AuthRequired,
    BadAuth,
    UnspecifiedTorError,
    InternalError,
    UnrecognizedEntity,
    InvalidConfigValue,
    InvalidDescriptor,
    UnmanagedEntity,
}

impl Into<u32> for TorErrorKind {
    fn into(self) -> u32 {
        use TorErrorKind::*;
        match self {
            TorErrorKind::ResourceExhausted => 451,
            TorErrorKind::SyntaxErrorProtocol => 500,
            TorErrorKind::UnrecognizedCmd => 510,
            TorErrorKind::UnimplementedCmd => 511,
            TorErrorKind::SyntaxErrorCmdArg => 512,
            TorErrorKind::UnrecognizedCmdArg => 513,
            TorErrorKind::AuthRequired => 514,
            TorErrorKind::BadAuth => 515,
            TorErrorKind::UnspecifiedTorError => 550,
            TorErrorKind::InternalError => 551,
            TorErrorKind::UnrecognizedEntity => 552,
            TorErrorKind::InvalidConfigValue => 553,
            TorErrorKind::InvalidDescriptor => 554,
            TorErrorKind::UnmanagedEntity => 555,
        }
    }
}

impl TryFrom<u16> for TorErrorKind {
    type Error = ();

    fn try_from(code: u16) -> Result<Self, ()> {
        match code {
            451 => Ok(TorErrorKind::ResourceExhausted),
            500 => Ok(TorErrorKind::SyntaxErrorProtocol),
            510 => Ok(TorErrorKind::UnrecognizedCmd),
            511 => Ok(TorErrorKind::UnimplementedCmd),
            512 => Ok(TorErrorKind::SyntaxErrorCmdArg),
            513 => Ok(TorErrorKind::UnrecognizedCmdArg),
            514 => Ok(TorErrorKind::AuthRequired),
            515 => Ok(TorErrorKind::BadAuth),
            550 => Ok(TorErrorKind::UnspecifiedTorError),
            551 => Ok(TorErrorKind::InternalError),
            552 => Ok(TorErrorKind::UnrecognizedEntity),
            553 => Ok(TorErrorKind::InvalidConfigValue),
            554 => Ok(TorErrorKind::InvalidDescriptor),
            555 => Ok(TorErrorKind::UnmanagedEntity),
            _ => Err(())
        }
    }
}
