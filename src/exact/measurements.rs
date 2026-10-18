//! Serialized costs, using decimal MB. Storage excludes transport framing;
//! communication includes each transmitted message's four-byte frame header.
use serde::Serialize;
use std::io;

pub const BYTES_PER_MB: f64 = 1_000_000.0;
pub fn mb(bytes: u64) -> f64 {
    bytes as f64 / BYTES_PER_MB
}
pub(crate) fn size<T: Serialize>(value: &T) -> io::Result<u64> {
    bincode::serialized_size(value).map_err(io::Error::other)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageCosts {
    pub ciphertext_bytes: u64,
    pub proof_bytes: u64,
}
impl StorageCosts {
    pub fn total_bytes(self) -> u64 {
        self.ciphertext_bytes + self.proof_bytes
    }
    pub fn message_bytes(self) -> u64 {
        self.total_bytes() + 4
    }
    pub(crate) fn report(self) {
        eprintln!(
            "[Target] Ciphertext Storage: {:.9} MB ({} bytes)",
            mb(self.ciphertext_bytes),
            self.ciphertext_bytes
        );
        eprintln!(
            "[Target] Proof Storage: {:.9} MB ({} bytes)",
            mb(self.proof_bytes),
            self.proof_bytes
        );
        eprintln!(
            "[Target] Total Storage: {:.9} MB ({} bytes)",
            mb(self.total_bytes()),
            self.total_bytes()
        );
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InteractionCosts {
    /// Nonzero only on the first interaction; later requests are prior updates.
    pub initial_target_send_bytes: u64,
    pub monitor_send_bytes: u64,
    pub target_storage: StorageCosts,
}
impl InteractionCosts {
    pub fn recurring_bytes(self) -> u64 {
        self.monitor_send_bytes + self.target_storage.message_bytes()
    }
    pub fn total_bytes(self) -> u64 {
        self.initial_target_send_bytes
            + self.monitor_send_bytes
            + self.target_storage.message_bytes()
    }
    pub(crate) fn report(self) {
        eprintln!(
            "[Target] Initial Target Send: {:.9} MB ({} bytes)",
            mb(self.initial_target_send_bytes),
            self.initial_target_send_bytes
        );
        eprintln!(
            "[Target] Monitor Send: {:.9} MB ({} bytes)",
            mb(self.monitor_send_bytes),
            self.monitor_send_bytes
        );
        eprintln!(
            "[Target] Updated Ciphertext: {:.9} MB ({} bytes)",
            mb(self.target_storage.ciphertext_bytes),
            self.target_storage.ciphertext_bytes
        );
        eprintln!(
            "[Target] Disjunction Proof: {:.9} MB ({} bytes)",
            mb(self.target_storage.proof_bytes),
            self.target_storage.proof_bytes
        );
        eprintln!(
            "[Target] Target Update Send: {:.9} MB ({} bytes)",
            mb(self.target_storage.message_bytes()),
            self.target_storage.message_bytes()
        );
        eprintln!(
            "[Target] Monitor + Target Update Communication: {:.9} MB ({} bytes)",
            mb(self.recurring_bytes()),
            self.recurring_bytes()
        );
        eprintln!(
            "[Target] Total Communication: {:.9} MB ({} bytes)",
            mb(self.total_bytes()),
            self.total_bytes()
        );
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn costs_use_decimal_mb_and_count_each_frame_once() {
        assert_eq!(mb(1_000_000), 1.0);
        let storage = StorageCosts {
            ciphertext_bytes: 200,
            proof_bytes: 300,
        };
        assert_eq!(storage.total_bytes(), 500);
        assert_eq!(storage.message_bytes(), 504);
        let first = InteractionCosts {
            initial_target_send_bytes: 704,
            monitor_send_bytes: 804,
            target_storage: storage,
        };
        assert_eq!(first.total_bytes(), 2012);
        let later = InteractionCosts {
            initial_target_send_bytes: 0,
            ..first
        };
        assert_eq!(later.total_bytes(), 1308);
    }
}
