use std::borrow::Cow;
use std::str::FromStr;

// note: torut DOES NOT IMPLEMENTS event parsing right now.
//  take a look at AsyncEventKind there are so many of them!

/// AsyncEvent is able to contain all info about async event which has been received from
/// tor process.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub struct AsyncEvent<'a> {
    /// code is tor's response code for asynchronous reply
    /// According to current torCP spec it should be set to 650 always but it may change in future.
    pub code: u16,

    /// lines contain raw response from tor process only minimally parsed by tor.
    /// Lines' content is not parsed at all. It's listener's responsibility to do so.
    pub lines: Vec<Cow<'a, str>>,
}

/// AsyncEventKind right now torCP implements some limited amount of kinds of events
/// `AsyncEventKind` represents these kinds which are known at the moment of writing this code.
///
/// # TorCP spec
/// Take a look at sections `4.1.*` which contain specification of all asynchronous events.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum AsyncEventKind {
    CircuitStatusChanged,
    StreamStatusChanged,
    ConnectionStatusChanged,
    BandwidthUsedInTheLastSecond,

    // 4.1.5. there are three constant strings after 650 code
    LogMessagesDebug,
    LogMessagesInfo,
    LogMessagesNotice,
    LogMessagesWarn,
    LogMessagesErr,

    NewDescriptorsAvailable,
    NewAddressMapping,
    DescriptorsUploadedToUsInOurRoleAsAuthoritativeServer,
    OurDescriptorChanged,

    // 4.1.10 there are three constant strings after 650 code
    StatusGeneral,
    StatusClient,
    StatusServer,

    OurSetOfGuardNodesHasChanged,
    NetworkStatusHasChanged,
    BandwidthUsedOnApplicationStream,
    PerCountryClientStats,
    NewConsensusNetworkStatusHasArrived,
    NewCircuitBuildTimeHasBeenSet,
    SignalReceived,
    ConfigurationChanged,
    CircuitStatusChangedSlightly,
    PluggableTransportLaunched,
    BandwidthUsedOnOROrDirOrExitConnection,
    BandwidthUsedByAllStreamsAttachedToACircuit,
    PerCircuitCellStatus,
    TokenBucketsRefilled,
    HiddenServiceDescriptors,
    HiddenServiceDescriptorsContent,
    NetworkLivenessHasChanged,
    PluggableTransportLogs,
    PluggableTransportStatus,
}

// hacky macro which generates from str and into string based on mapping
// so I do not have to write same strings twice.

// 2do: move enum definition into this macro
macro_rules! generate_from_into {
    {
        $typename:ident {
            $(
                // me: $enum_var:expr => $value:expr
                // rustc: "arbitrary expressions aren't allowed in patterns"
                $enum_var:ident => $value:tt
            ),*
        }
    } => {
        impl $typename {
            /// get_identifier returns single word contained after 650 code
            /// used to identify event.
            ///
            /// # Note
            /// I haven't seen torCP specify this as "the good" way of identifying event.
            /// But seems like until now all events are differentiated from each other this way.
            pub fn get_identifier(/*& it's copy type*/ self) -> &'static str {
                match self {
                    $(
                        Self::$enum_var => $value
                    ),*
                }
            }
        }

        impl Into<&'static str> for $typename {
            fn into(self) -> &'static str{
                self.get_identifier()
            }
        }

        // TODO(teawithsand): implement some function to get kind from first line of string
        //  rather than manually parsing it(split by space should work anyway)

        impl FromStr for $typename {
            type Err = ();

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let res = match s {
                    $(
                        $value => Self::$enum_var,
                    )*
                    _ => {
                        return Err(());
                    }
                };
                Ok(res)
            }
        }
    }
}

/*
AsyncEventKind::CircuitStatusChanged => "CIRC",
AsyncEventKind::StreamStatusChanged => "STREAM",
AsyncEventKind::ConnectionStatusChanged => "ORCONN",
AsyncEventKind::BandwidthUsedInTheLastSecond => "BW",

AsyncEventKind::LogMessagesDebug => "DEBUG",
AsyncEventKind::LogMessagesInfo => "INFO",
AsyncEventKind::LogMessagesNotice => "NOTICE",
AsyncEventKind::LogMessagesWarn => "WARN",
AsyncEventKind::LogMessagesErr => "ERR",

AsyncEventKind::NewDescriptorsAvailable => "NEWDESC",
AsyncEventKind::NewAddressMapping => "ADDRMAP",
AsyncEventKind::DescriptorsUploadedToUsInOurRoleAsAuthoritativeServer => "AUTHDIR_NEWDESCS",
AsyncEventKind::OurDescriptorChanged => "DESCCHANGED",

AsyncEventKind::StatusGeneral => "STATUS_GENERAL",
AsyncEventKind::StatusClient => "STATUS_CLIENT",
AsyncEventKind::StatusServer => "STATUS_SERVER",

AsyncEventKind::OurSetOfGuardNodesHasChanged => "GUARD",
AsyncEventKind::NetworkStatusHasChanged => "NS",
AsyncEventKind::BandwidthUsedOnApplicationStream => "STREAM_BW",
AsyncEventKind::PerCountryClientStats => "CLIENTS_SEEN",
AsyncEventKind::NewConsensusNetworkStatusHasArrived => "NEWCONSENSUS",
AsyncEventKind::NewCircuitBuildTimeHasBeenSet => "BUILDTIMEOUT_SET",
AsyncEventKind::SignalReceived => "SIGNAL",
AsyncEventKind::ConfigurationChanged => "CONF_CHANGED",
AsyncEventKind::CircuitStatusChangedSlightly => "CIRC_MINOR",
AsyncEventKind::PluggableTransportLaunched => "TRANSPORT_LAUNCHED",
AsyncEventKind::BandwidthUsedOnOROrDirOrExitConnection => "CONN_BW",
AsyncEventKind::BandwidthUsedByAllStreamsAttachedToACircuit => "CIRC_BW",
AsyncEventKind::PerCircuitCellStatus => "CELL_STATS",
AsyncEventKind::TokenBucketsRefilled => "TB_EMPTY",
AsyncEventKind::HiddenServiceDescriptors => "HS_DESC",
AsyncEventKind::HiddenServiceDescriptorsContent => "HS_DESC_CONTENT",
AsyncEventKind::NetworkLivenessHasChanged => "NETWORK_LIVENESS",
AsyncEventKind::PluggableTransportLogs => "PT_LOG",
AsyncEventKind::PluggableTransportStatus => "PT_STATUS",
*/

generate_from_into! {
    AsyncEventKind {
        CircuitStatusChanged => "CIRC",
        StreamStatusChanged => "STREAM",
        ConnectionStatusChanged => "ORCONN",
        BandwidthUsedInTheLastSecond => "BW",

        LogMessagesDebug => "DEBUG",
        LogMessagesInfo => "INFO",
        LogMessagesNotice => "NOTICE",
        LogMessagesWarn => "WARN",
        LogMessagesErr => "ERR",

        NewDescriptorsAvailable => "NEWDESC",
        NewAddressMapping => "ADDRMAP",
        DescriptorsUploadedToUsInOurRoleAsAuthoritativeServer => "AUTHDIR_NEWDESCS",
        OurDescriptorChanged => "DESCCHANGED",

        StatusGeneral => "STATUS_GENERAL",
        StatusClient => "STATUS_CLIENT",
        StatusServer => "STATUS_SERVER",

        OurSetOfGuardNodesHasChanged => "GUARD",
        NetworkStatusHasChanged => "NS",
        BandwidthUsedOnApplicationStream => "STREAM_BW",
        PerCountryClientStats => "CLIENTS_SEEN",
        NewConsensusNetworkStatusHasArrived => "NEWCONSENSUS",
        NewCircuitBuildTimeHasBeenSet => "BUILDTIMEOUT_SET",
        SignalReceived => "SIGNAL",
        ConfigurationChanged => "CONF_CHANGED",
        CircuitStatusChangedSlightly => "CIRC_MINOR",
        PluggableTransportLaunched => "TRANSPORT_LAUNCHED",
        BandwidthUsedOnOROrDirOrExitConnection => "CONN_BW",
        BandwidthUsedByAllStreamsAttachedToACircuit => "CIRC_BW",
        PerCircuitCellStatus => "CELL_STATS",
        TokenBucketsRefilled => "TB_EMPTY",
        HiddenServiceDescriptors => "HS_DESC",
        HiddenServiceDescriptorsContent => "HS_DESC_CONTENT",
        NetworkLivenessHasChanged => "NETWORK_LIVENESS",
        PluggableTransportLogs => "PT_LOG",
        PluggableTransportStatus => "PT_STATUS"
    }
}

/*
// implemented by above macro
impl AsyncEventKind {
    /// get_identifier returns single word contained after 650 code
    /// used to identify event.
    ///
    /// # Note
    /// I haven't seen torCP specify this as "the good" way of identifying event.
    /// But seems like until now all events are differentiated from each other this way.
    pub fn get_identifier(&self) -> &'static str {
        match self {
            AsyncEventKind::CircuitStatusChanged => "CIRC",
            AsyncEventKind::StreamStatusChanged => "STREAM",
            AsyncEventKind::ConnectionStatusChanged => "ORCONN",
            AsyncEventKind::BandwidthUsedInTheLastSecond => "BW",

            AsyncEventKind::LogMessagesDebug => "DEBUG",
            AsyncEventKind::LogMessagesInfo => "INFO",
            AsyncEventKind::LogMessagesNotice => "NOTICE",
            AsyncEventKind::LogMessagesWarn => "WARN",
            AsyncEventKind::LogMessagesErr => "ERR",

            AsyncEventKind::NewDescriptorsAvailable => "NEWDESC",
            AsyncEventKind::NewAddressMapping => "ADDRMAP",
            AsyncEventKind::DescriptorsUploadedToUsInOurRoleAsAuthoritativeServer => "AUTHDIR_NEWDESCS",
            AsyncEventKind::OurDescriptorChanged => "DESCCHANGED",

            AsyncEventKind::StatusGeneral => "STATUS_GENERAL",
            AsyncEventKind::StatusClient => "STATUS_CLIENT",
            AsyncEventKind::StatusServer => "STATUS_SERVER",

            AsyncEventKind::OurSetOfGuardNodesHasChanged => "GUARD",
            AsyncEventKind::NetworkStatusHasChanged => "NS",
            AsyncEventKind::BandwidthUsedOnApplicationStream => "STREAM_BW",
            AsyncEventKind::PerCountryClientStats => "CLIENTS_SEEN",
            AsyncEventKind::NewConsensusNetworkStatusHasArrived => "NEWCONSENSUS",
            AsyncEventKind::NewCircuitBuildTimeHasBeenSet => "BUILDTIMEOUT_SET",
            AsyncEventKind::SignalReceived => "SIGNAL",
            AsyncEventKind::ConfigurationChanged => "CONF_CHANGED",
            AsyncEventKind::CircuitStatusChangedSlightly => "CIRC_MINOR",
            AsyncEventKind::PluggableTransportLaunched => "TRANSPORT_LAUNCHED",
            AsyncEventKind::BandwidthUsedOnOROrDirOrExitConnection => "CONN_BW",
            AsyncEventKind::BandwidthUsedByAllStreamsAttachedToACircuit => "CIRC_BW",
            AsyncEventKind::PerCircuitCellStatus => "CELL_STATS",
            AsyncEventKind::TokenBucketsRefilled => "TB_EMPTY",
            AsyncEventKind::HiddenServiceDescriptors => "HS_DESC",
            AsyncEventKind::HiddenServiceDescriptorsContent => "HS_DESC_CONTENT",
            AsyncEventKind::NetworkLivenessHasChanged => "NETWORK_LIVENESS",
            AsyncEventKind::PluggableTransportLogs => "PT_LOG",
            AsyncEventKind::PluggableTransportStatus => "PT_STATUS",
        }
    }
}
*/