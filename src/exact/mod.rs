#[cfg(test)]
mod benchmarks;
mod division;
pub mod measurements;
pub mod monitor;
pub mod performance;
pub mod proofs;
pub mod target;

/// Exact-only options. Both modes use division; `pok` enables the target initial/OR proofs.
#[derive(Clone, Copy, Debug)]
pub struct ProtocolConfig {
    pub pok: bool,
    /// Deployment-only measurement when true; measured update interactions when false.
    pub round1: bool,
}
impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            pok: false,
            round1: true,
        }
    }
}

impl ProtocolConfig {
    /// Parse exact-specific flags without changing the executable's positional arguments.
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        let mut config = Self::default();
        let mut seen_pok = false;
        let mut seen_round1 = false;
        for (i, arg) in args.iter().enumerate() {
            let (seen, value) = match arg.as_str() {
                "--pok" => (&mut seen_pok, &mut config.pok),
                "--round1" => (&mut seen_round1, &mut config.round1),
                _ => continue,
            };
            if *seen {
                return Err(format!("duplicate {arg}"));
            }
            *value = args
                .get(i + 1)
                .ok_or_else(|| format!("{arg} requires true or false"))?
                .parse()
                .map_err(|_| format!("{arg} requires true or false"))?;
            *seen = true;
        }
        Ok(config)
    }
    pub(crate) fn resolve(self) -> Result<Self, String> {
        let args: Vec<_> = std::env::args().collect();
        let cli = Self::from_args(&args)?;
        Ok(Self {
            pok: self.pok || cli.pok,
            round1: if args.iter().any(|s| s == "--round1") {
                cli.round1
            } else {
                self.round1
            },
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct SessionHello {
    magic: [u8; 16],
    nonce: [u8; 32],
    pok: bool,
    round1: bool,
}
impl SessionHello {
    #[cfg(test)]
    pub(crate) fn fresh() -> Self {
        Self::fresh_for_mode(true)
    }
    #[cfg(test)]
    pub(crate) fn fresh_for_mode(pok: bool) -> Self {
        Self::fresh_for_config(ProtocolConfig { pok, round1: false })
    }
    pub(crate) fn fresh_for_config(config: ProtocolConfig) -> Self {
        use rand::RngCore;
        let mut nonce = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Self {
            magic: *b"exact-pok-v4!!!!",
            nonce,
            pok: config.pok,
            round1: config.round1,
        }
    }
    pub(crate) fn session(&self, peer: &Self) -> std::io::Result<[u8; 32]> {
        if self.magic != *b"exact-pok-v4!!!!"
            || self.magic != peer.magic
            || self.pok != peer.pok
            || self.round1 != peer.round1
        {
            return Err(std::io::Error::other(
                "exact protocol version, pok, or round1 mismatch",
            ));
        }
        let mut t = merlin::Transcript::new(b"exact-pok-session-v4");
        t.append_message(b"version", &self.magic);
        t.append_u64(b"pok", u64::from(self.pok));
        t.append_u64(b"round1", u64::from(self.round1));
        t.append_message(b"target", &self.nonce);
        t.append_message(b"monitor", &peer.nonce);
        let mut session = [0; 32];
        t.challenge_bytes(b"session", &mut session);
        Ok(session)
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum TPolyProof {
    Initial(proofs::InitialPoK),
    RerandomizationOr(proofs::OrRerandProof),
}

#[cfg(test)]
mod config_tests {
    use super::*;
    #[test]
    fn sessions_bind_both_nonces_version_and_local_mode() {
        let a = SessionHello::fresh_for_mode(true);
        let b = SessionHello::fresh_for_mode(true);
        let session = a.session(&b).unwrap();
        let other = SessionHello::fresh_for_mode(true);
        assert_ne!(session, a.session(&other).unwrap());
        assert_ne!(session, other.session(&b).unwrap());
        assert_ne!(session, b.session(&a).unwrap());
        let disabled = SessionHello::fresh_for_mode(false);
        assert!(a.session(&disabled).is_err());
        assert!(disabled.session(&a).is_err());
        let deployment = SessionHello::fresh_for_config(ProtocolConfig {
            pok: true,
            round1: true,
        });
        assert!(a.session(&deployment).is_err());
        assert!(deployment.session(&a).is_err());
        let mut wrong = SessionHello::fresh_for_mode(true);
        wrong.magic = *b"exact-pok-v3!!!!";
        assert!(a.session(&wrong).is_err());
        wrong.magic[0] ^= 1;
        assert!(wrong.session(&b).is_err());
        assert!(a.session(&wrong).is_err());
    }
    #[test]
    fn explicit_boolean_mode() {
        let parse = |args: &[&str]| {
            ProtocolConfig::from_args(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        assert!(!parse(&[]).unwrap().pok);
        assert!(parse(&[]).unwrap().round1);
        assert!(!parse(&["--round1", "false"]).unwrap().round1);
        assert!(parse(&["--round1", "true"]).unwrap().round1);
        assert!(parse(&["--round1"]).is_err());
        assert!(parse(&["--round1", "yes"]).is_err());
        assert!(parse(&["--round1", "true", "--round1", "false"]).is_err());
        let both = parse(&["--round1", "false", "--pok", "true"]).unwrap();
        assert!(both.pok);
        assert!(!both.round1);
        assert!(parse(&["--pok", "true"]).unwrap().pok);
        assert!(!parse(&["--pok", "false"]).unwrap().pok);
        assert!(parse(&["--pok"]).is_err());
        assert!(parse(&["--pok", "yes"]).is_err());
        assert!(parse(&["--pok", "true", "--pok", "false"]).is_err());
    }
}
