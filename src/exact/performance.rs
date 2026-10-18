//! Public, deterministic generator reuse. No witnesses or proof nonces are cached.
use bulletproofs::BulletproofGens;
use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint, scalar::Scalar,
};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Instant,
};
static GENERATORS: OnceLock<Mutex<BTreeMap<usize, Arc<BulletproofGens>>>> = OnceLock::new();
static BUILDS: AtomicU64 = AtomicU64::new(0);
static BUILD_NS: AtomicU64 = AtomicU64::new(0);
static HITS: AtomicU64 = AtomicU64::new(0);
/// Process-wide public setup counters. Deltas can include both local endpoints.
#[derive(Clone, Copy, Debug, Default)]
pub struct GeneratorActivity {
    pub builds: u64,
    pub setup_ns: u64,
    pub hits: u64,
}
impl GeneratorActivity {
    pub fn since(self, earlier: Self) -> Self {
        Self {
            builds: self.builds.saturating_sub(earlier.builds),
            setup_ns: self.setup_ns.saturating_sub(earlier.setup_ns),
            hits: self.hits.saturating_sub(earlier.hits),
        }
    }
    pub(crate) fn report(self) {
        eprintln!("[Target] Public Generator Cache: builds={} setup={:.3} ms hits={} (setup included in measured latency)",self.builds,self.setup_ns as f64/1_000_000.0,self.hits);
    }
}
pub fn generator_activity() -> GeneratorActivity {
    GeneratorActivity {
        builds: BUILDS.load(Ordering::Relaxed),
        setup_ns: BUILD_NS.load(Ordering::Relaxed),
        hits: HITS.load(Ordering::Relaxed),
    }
}
pub(crate) fn generators(multipliers: usize) -> Arc<BulletproofGens> {
    // Every caller validates its dimensions to <=4096 before requesting setup.
    // Only capacities 64,128,...,4096 are retained, bounding cache memory.
    assert!(
        multipliers <= 4096,
        "exact circuit capacity exceeds protocol limit"
    );
    let capacity = multipliers.next_power_of_two().max(64);
    let cache = GENERATORS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(gens) = cache.get(&capacity) {
        HITS.fetch_add(1, Ordering::Relaxed);
        return Arc::clone(gens);
    }
    let start = Instant::now();
    let gens = Arc::new(BulletproofGens::new(capacity, 1));
    BUILD_NS.fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
    BUILDS.fetch_add(1, Ordering::Relaxed);
    cache.insert(capacity, Arc::clone(&gens));
    gens
}
pub(crate) fn mul_g(s: &Scalar) -> RistrettoPoint {
    s * &RISTRETTO_BASEPOINT_TABLE
}
/// Only the opt-in, serial benchmark uses this; ordinary tests never reset setup.
#[cfg(test)]
pub(crate) fn reset_for_benchmark() {
    if let Some(cache) = GENERATORS.get() {
        cache.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
    BUILDS.store(0, Ordering::Relaxed);
    BUILD_NS.store(0, Ordering::Relaxed);
    HITS.store(0, Ordering::Relaxed);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_generators_are_shared_by_capacity() {
        let a = generators(65);
        let b = generators(127);
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.gens_capacity, 128);
        assert_eq!(generators(0).gens_capacity, 64);
        assert_eq!(generators(1000).gens_capacity, 1024);
    }
}
