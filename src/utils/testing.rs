use crate::utils::{AutoKillChild, run_tor};

const ENV_VAR_NAME: &str = "TORUT_TESTING_TOR_BINARY";

// TODO(teawithsand): more this port to enviroment variable
/// TOR_TESTING_PORT used as default testing port for tor control proto listener
pub(crate) const TOR_TESTING_PORT: u16 = 49625;

/// run_testing_tor_instance creates tor process which is used for testing purposes
///
/// It takes tor binary path from env during runtime and should be used only during test builds.
/// It also tires to reset tor's env vars in order to provide reproducible tests.
///
/// It also automatically waits until tor control proto port becomes available
pub(crate) fn run_testing_tor_instance<A, T>(args: A) -> AutoKillChild
    where
        A: AsRef<[T]>,
        T: AsRef<str>
{
    let tor_path = std::env::var(ENV_VAR_NAME).unwrap();
    let mut c = AutoKillChild::from(run_tor(tor_path, args).unwrap());
    c
}

#[cfg(test)]
mod test {
    pub use super::*;

    #[test]
    fn test_can_run_very_basic_tor_instance() {
        let c = run_testing_tor_instance(&["--DisableNetwork", "1", "--ControlPort", &TOR_TESTING_PORT.to_string()]);
        // c.kill().unwrap();
    }
}