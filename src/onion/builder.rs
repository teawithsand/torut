//! Builder service module contains things required to spin up new onion service on local machine

// TODO(teawithsand): Cleanup this builder stuff

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Display;
use std::net::IpAddr;

#[cfg(feature = "v3")]
use crate::onion::{TorPublicKeyV3, TorSecretKeyV3};
use crate::onion::common::TorSecretKey;

#[derive(Debug, Clone)]
pub struct OnionServiceBuilder {
    pub(crate) key: Option<TorSecretKey>,
    pub(crate) ports_mapping: HashMap<u16, IpAddr>,
    pub(crate) max_streams: Option<u16>,
    pub(crate) client_auth: HashMap<String, String>,
    pub(crate) onion_service_flags: HashSet<OnionServiceFlag>,
}

#[derive(Debug, Copy, Clone)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum OnionServiceFlag {
    DiscardPK,
    Detach,
    // BasicAuth, // Not set here. Set client_auth in order to set basic_auth flag
    NonAnonymous,
    MaxStreamsCloseCircuit,
}

impl Display for OnionServiceFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let text = match self {
            OnionServiceFlag::Detach => "Detach",
            OnionServiceFlag::DiscardPK => "DiscardPK",
            OnionServiceFlag::NonAnonymous => "NonAnonymous",
            OnionServiceFlag::MaxStreamsCloseCircuit => "MaxStreamsCloseCircuit",
        };
        write!(f, "{}", text)
    }
}

impl OnionServiceBuilder {
    pub fn new() -> Self {
        Self {
            key: None,
            ports_mapping: HashMap::new(),
            max_streams: None,
            client_auth: HashMap::new(),
            onion_service_flags: HashSet::new(),
        }
    }

    pub fn set_key(&mut self, sk: TorSecretKey) {
        self.key = Some(sk);
    }

    pub fn set_max_streams(&mut self, streams: u16) {
        self.max_streams = Some(streams);
    }

    pub fn set_port_mapping(&mut self, local: IpAddr, remote: u16) {
        self.ports_mapping.insert(remote, local);
    }

    pub fn set_flags(&mut self, flags: HashSet<OnionServiceFlag>) {
        self.onion_service_flags = flags;
    }
}

pub enum RunningOnionServiceKeyPair {
    #[cfg(feature = "v3")]
    V3(TorPublicKeyV3, TorSecretKeyV3),
}

/// RunningOnionService represents
pub struct RunningOnionService {
    pub flags: HashSet<OnionServiceFlag>,
    pub key_pair: RunningOnionServiceKeyPair,
    pub client_auth: HashMap<String, String>,
}
