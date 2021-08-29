use std::io::{BufRead, BufReader};
use std::ops::{Deref, DerefMut};
use std::process::{Child, Command, Stdio};

/// AutoKillChild is kind of bag which contains `Child`.
/// It makes it automatically commit suicide after it gets dropped.
/// 
/// It's designed to be used with tor running in rust application. AKC guarantees killing tor application on exit.
/// Note: It ignores process killing error in Drop.
pub struct AutoKillChild {
    child: Option<Child>,
}

impl From<Child> for AutoKillChild {
    fn from(c: Child) -> Self{
        Self::new(c)
    }
}

impl AutoKillChild {
    pub fn new(c: Child) -> Self{
        Self{
            child: Some(c)
        }
    }

    /// into_inner takes child from AutoKillChild.
    /// It prevents child from dying automatically after it's dropped.
    pub fn into_inner(mut self) -> Child {
        self.child.take().unwrap()
    }
}

impl Drop for AutoKillChild {
    fn drop(&mut self) {
        if let Some(c) = &mut self.child {
            // do not unwrap. Process might have died already.
            let _ = c.kill();
        }
    }
}

impl Deref for AutoKillChild {
    type Target = Child;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.child.as_ref().unwrap()
    }
}

impl DerefMut for AutoKillChild {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.child.as_mut().unwrap()
    }
}

// TODO(teawithsand): add bootstrapping runner here
/// run_tor runs new tor from specified path with specified args.
/// It should not be used when control port is disabled.
/// 
/// # Parameters
/// * `path` - path to run tor binary. Note: if not found rust will query $PATH see docs for `std::process::Command::new`
/// * `args` - cli args provided to tor binary in raw form - array of strings. Format should be like: ["--DisableNetwork", "1"]
/// 
/// For arguments reference take a look at: https://www.torproject.org/docs/tor-manual.html.en
/// 
/// # Common parameters
/// 1. CookieAuthentication 1 - enables cookie authentication, since null may not be safe in some contexts
/// 2. ControlPort PORT - sets control port which should be used by tor controller, like torut, to controll this instance of tor.
/// 
/// # Result detection note
/// It exists after finding "Opened Control listener" in the stdout.
/// Tor may *not* print such text to stdout. In that case this function will never exit(unless tor process dies).
/// 
/// # Stdout note
/// This function uses `std::io::BufReader` to read data from stdout in order to decide if tor is running or not.
/// Dropping buf_reader drops it's internal buffer with data, which may cause partial data loss.
/// 
/// For most cases it's fine, so it probably won't be fixed.
/// Alternative to this is char-by-char reading which is slower but should be also fine here.
pub fn run_tor<A, T, P>(path: P, args: A) -> Result<Child, std::io::Error>
    where
        A: AsRef<[T]>,
        T: AsRef<str>,
        P: AsRef<str>,
{
    let path = path.as_ref();
    let mut c = Command::new(path)
        .args(args.as_ref().iter().map(|t| t.as_ref()))
        // .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()?;
    {
        // Stdio is piped so this works
        {
            let mut stdout = BufReader::new(c.stdout.as_mut().unwrap());

            loop {
                // wait until tor starts
                // hacky but works
                // stem does something simmilar internally but they use regexes to match bootstrapping messages from tor
                //
                // https://stem.torproject.org/_modules/stem/process.html#launch_tor

                let mut l = String::new();
                match stdout.read_line(&mut l) {
                    Ok(v) => v,
                    Err(e) => {
                        // kill if tor process hasn't died already
                        // this should make sure that tor process is not alive *almost* always
                        let _ = c.kill(); 
                        return Err(e);
                    }
                };

                if l.contains("Opened Control listener") {
                    break;
                }
            }
            
            // buffered stdout is dropped here.
            // It may cause partial data loss but it's better than dropping child.
        }
    }
    Ok(c)
}

// TODO(teawithsand): async run_tor

// tests for these are in testing.rs