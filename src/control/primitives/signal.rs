use std::fmt::Display;
use std::str::FromStr;

/// TorSignal describes tor's SIGNAL command argument
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serialize", derive(Serialize, Deserialize))]
pub enum TorSignal {
    // https://gitweb.torproject.org/torspec.git/tree/control-spec.txt
    // line 429
    Reload,
    Shutdown,
    Dump,
    Debug,
    Halt,
    Hup,
    Int,
    Usr1,
    Usr2,
    Term,
    NewNym,
    ClearDNSCache,
    Heartbeat,
    Active,
    Dormant,
}


impl Display for TorSignal {
    //noinspection SpellCheckingInspection
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        let text = match self {
            TorSignal::Reload => "RELOAD",
            TorSignal::Shutdown => "SHUTDOWN",
            TorSignal::Dump => "DUMP",
            TorSignal::Debug => "DEBUG",
            TorSignal::Halt => "HALT",
            TorSignal::Hup => "HUP",
            TorSignal::Int => "INT",
            TorSignal::Usr1 => "USR1",
            TorSignal::Usr2 => "USR2",
            TorSignal::Term => "TERM",
            TorSignal::NewNym => "NEWNYM",
            TorSignal::ClearDNSCache => "CLEARDNSCACHE",
            TorSignal::Heartbeat => "HEARTBEAT",
            TorSignal::Active => "ACTIVE",
            TorSignal::Dormant => "DORMANT",
        };
        write!(f, "{}", text)
    }
}

impl FromStr for TorSignal {
    type Err = ();

    //noinspection SpellCheckingInspection
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let signal = match s {
            "RELOAD" => TorSignal::Reload,
            "SHUTDOWN" => TorSignal::Shutdown,
            "DUMP" => TorSignal::Dump,
            "DEBUG" => TorSignal::Debug,
            "HALT" => TorSignal::Halt,
            "HUP" => TorSignal::Hup,
            "INT" => TorSignal::Int,
            "USR1" => TorSignal::Usr1,
            "USR2" => TorSignal::Usr2,
            "TERM" => TorSignal::Term,
            "NEWNYM" => TorSignal::NewNym,
            "CLEARDNSCACHE" => TorSignal::ClearDNSCache,
            "HEARTBEAT" => TorSignal::Heartbeat,
            "ACTIVE" => TorSignal::Active,
            "DORMANT" => TorSignal::Dormant,
            _ => return Err(()),
        };
        Ok(signal)
    }
}
