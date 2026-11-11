//! Serialized costs, using decimal MB. Storage excludes transport framing;
//! monitor send includes framing; requested update communication adds next target payload.
//! `total_bytes` also counts target framing and the initial upload for full wire accounting.
use serde::Serialize;
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};

pub const BYTES_PER_MB: f64 = 1_000_000.0;
pub fn mb(bytes: u64) -> f64 {
    bytes as f64 / BYTES_PER_MB
}
/// Four significant digits, including trailing zeros; avoid rounding small values to zero.
pub fn significant(value: f64) -> String {
    let scientific = format!("{value:.3e}");
    if let Some((_, exponent)) = scientific.split_once('e') {
        if let Ok(exponent) = exponent.parse::<i32>() {
            if (-4..4).contains(&exponent) {
                return format!("{:.*}", (3 - exponent) as usize, value);
            }
        }
    }
    scientific
}
/// Both endpoints use the same wall clock in the demo. Separate hosts need synchronized clocks.
pub(crate) fn unix_ns() -> io::Result<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .map_err(io::Error::other)
}
pub(crate) fn elapsed_seconds(started: u128, stored: u128) -> io::Result<f64> {
    stored
        .checked_sub(started)
        .map(|ns| ns as f64 / 1_000_000_000.0)
        .ok_or_else(|| {
            io::Error::other(
                "monitor start is after target storage time; synchronize endpoint clocks",
            )
        })
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
            "[Target] Ciphertext Storage: {} MB",
            significant(mb(self.ciphertext_bytes))
        );
        eprintln!(
            "[Target] Proof Storage: {} MB",
            significant(mb(self.proof_bytes))
        );
        eprintln!(
            "[Target] Total Storage: {} MB",
            significant(mb(self.total_bytes()))
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
    /// Requested update communication: monitor frame plus next target ciphertext/proof payload.
    pub fn recurring_bytes(self) -> u64 {
        self.monitor_send_bytes + self.target_storage.total_bytes()
    }
    pub fn total_bytes(self) -> u64 {
        self.initial_target_send_bytes
            + self.monitor_send_bytes
            + self.target_storage.message_bytes()
    }
    pub(crate) fn report(self) {
        eprintln!(
            "[Target] Monitor Send: {} MB",
            significant(mb(self.monitor_send_bytes))
        );
        eprintln!(
            "[Target] New Storage (ciphertext + disjunction proof): {} MB",
            significant(mb(self.target_storage.total_bytes()))
        );
        eprintln!(
            "[Target] Communication (monitor send + next target payload): {} MB",
            significant(mb(self.recurring_bytes()))
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
        assert_eq!(first.recurring_bytes(), 1304);
        let later = InteractionCosts {
            initial_target_send_bytes: 0,
            ..first
        };
        assert_eq!(later.total_bytes(), 1308);
    }
    #[test]
    fn output_uses_four_significant_digits_across_scales_and_rounding_carry() {
        for (value, expected) in [
            (0.0, "0.000"),
            (1.0, "1.000"),
            (12.3456, "12.35"),
            (0.00123456, "0.001235"),
            (0.000123456, "0.0001235"),
            (0.0000123456, "1.235e-5"),
            (0.00099996, "0.001000"),
            (9999.6, "1.000e4"),
            (123456.0, "1.235e5"),
        ] {
            assert_eq!(significant(value), expected);
        }
    }
    #[test]
    fn latency_uses_monitor_start_and_target_storage_end_in_seconds() {
        let start = 1_800_000_000_000_000_000u128;
        assert_eq!(
            elapsed_seconds(start, start + 1_234_000_000).unwrap(),
            1.234
        );
        assert!(elapsed_seconds(start, start - 1).is_err());
    }
}
