use std::collections::HashSet;

use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;
use rand::Rng;

#[derive(Clone, Copy, Debug)]
pub struct BloomFilterConfig {
    pub bloom_filter_size: usize,
    pub hash_count: usize,
    pub target_marked_count: usize,
}

impl BloomFilterConfig {
    pub fn validate(self) -> Result<Self, String> {
        if self.bloom_filter_size == 0 {
            return Err("bloom filter size must be greater than zero".to_string());
        }
        if self.hash_count == 0 {
            return Err("hash count k must be greater than zero".to_string());
        }
        if self.hash_count > self.bloom_filter_size {
            return Err("hash count k must be at most the bloom filter size".to_string());
        }
        if self.target_marked_count > self.bloom_filter_size {
            return Err(
                "target marked-position count must be at most the bloom filter size".to_string(),
            );
        }
        Ok(self)
    }
}

/// Choose a public Bloom-filter hash count `k` from the Bernoulli-honeyword
/// relation `(|B| / b)^k = p_h`.
///
/// We pick the smallest integer `k` that keeps the expected bit density near
/// `1/2`, which is the usual Bloom-filter sweet spot and also keeps later ZK
/// proofs cheaper because both hashing witnesses and proof size scale with `k`.
pub fn recommended_hash_count(honeyword_probability: f64) -> usize {
    if !honeyword_probability.is_finite()
        || honeyword_probability <= 0.0
        || honeyword_probability >= 1.0
    {
        return 1;
    }

    let target_density = 0.5f64;
    let k = (honeyword_probability.ln() / target_density.ln()).round() as isize;
    k.max(1) as usize
}

pub fn scalar_positions(input: Scalar, config: BloomFilterConfig) -> Vec<Scalar> {
    let base = scalar_to_usize(input);
    let usable_span = usable_input_span(config);
    assert!(
        (1..=usable_span).contains(&base),
        "input scalar must lie in the supported Bloom-hash domain"
    );
    (0..config.hash_count)
        .map(|hash_index| hash_position(input, hash_index, config))
        .collect()
}

pub fn sample_marked_positions(
    rng: &mut OsRng,
    config: BloomFilterConfig,
    required_positions: &[Scalar],
) -> Vec<Scalar> {
    let mut universe: Vec<Scalar> = (1..=config.bloom_filter_size)
        .map(|position| Scalar::from(position as u64))
        .collect();

    let mut marked_positions = dedup_positions(required_positions);
    let target_count = config.target_marked_count.max(marked_positions.len());
    if target_count == marked_positions.len() {
        return marked_positions;
    }

    let marked_set: HashSet<[u8; 32]> = marked_positions.iter().map(|p| p.to_bytes()).collect();
    universe.retain(|position| !marked_set.contains(&position.to_bytes()));
    for i in (1..universe.len()).rev() {
        let j = rng.gen_range(0..=i);
        universe.swap(i, j);
    }

    marked_positions.extend(
        universe
            .into_iter()
            .take(target_count - marked_positions.len()),
    );
    marked_positions
}

pub fn scalar_is_member(
    input: Scalar,
    marked_positions: &[Scalar],
    config: BloomFilterConfig,
) -> bool {
    let marked_set: HashSet<[u8; 32]> = marked_positions.iter().map(|p| p.to_bytes()).collect();
    scalar_positions(input, config)
        .into_iter()
        .all(|position| marked_set.contains(&position.to_bytes()))
}

pub fn find_non_member_scalar(
    marked_positions: &[Scalar],
    config: BloomFilterConfig,
) -> Option<Scalar> {
    let usable_span = usable_input_span(config);
    for candidate in 1..=usable_span as u64 {
        let candidate = Scalar::from(candidate);
        if !scalar_is_member(candidate, marked_positions, config) {
            return Some(candidate);
        }
    }

    None
}

pub fn dedup_positions(positions: &[Scalar]) -> Vec<Scalar> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for &position in positions {
        if seen.insert(position.to_bytes()) {
            deduped.push(position);
        }
    }
    deduped
}

pub fn sample_query_scalar<R: Rng + ?Sized>(rng: &mut R, config: BloomFilterConfig) -> Scalar {
    let usable_span = usable_input_span(config);
    Scalar::from(rng.gen_range(1..=usable_span as u64))
}

pub fn hash_params(hash_index: usize) -> (Scalar, Scalar) {
    (
        Scalar::from((hash_index + 1) as u64),
        Scalar::from(hash_index as u64),
    )
}

pub fn hash_position(input: Scalar, hash_index: usize, config: BloomFilterConfig) -> Scalar {
    let input_scalar = scalar_to_usize(input);
    let usable_span = usable_input_span(config);
    assert!(
        (1..=usable_span).contains(&input_scalar),
        "input scalar must lie in the supported Bloom-hash domain"
    );
    let (slope, intercept) = hash_params(hash_index);
    slope * input + intercept
}

pub fn usable_input_span(config: BloomFilterConfig) -> usize {
    let max_slope = config.hash_count;
    let max_intercept = config.hash_count.saturating_sub(1);
    if config.bloom_filter_size <= max_intercept {
        return 0;
    }
    (config.bloom_filter_size - max_intercept) / max_slope
}

pub fn scalar_to_usize(input: Scalar) -> usize {
    let bytes = input.to_bytes();
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[..8]);
    let raw = u64::from_le_bytes(arr);
    raw as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_positions_are_in_range() {
        let config = BloomFilterConfig {
            bloom_filter_size: 32,
            hash_count: 3,
            target_marked_count: 16,
        };
        let positions = scalar_positions(Scalar::from(3u64), config);
        assert_eq!(positions.len(), 3);
        assert_eq!(
            positions,
            vec![Scalar::from(3u64), Scalar::from(7u64), Scalar::from(11u64)]
        );
    }

    #[test]
    fn test_hash_positions_stay_within_bloom_filter_range() {
        let config = BloomFilterConfig {
            bloom_filter_size: 32,
            hash_count: 3,
            target_marked_count: 16,
        };
        let max_input = Scalar::from(usable_input_span(config) as u64);
        let positions = scalar_positions(max_input, config);
        for position in positions {
            let value = scalar_to_usize(position);
            assert!((1..=config.bloom_filter_size).contains(&value));
        }
    }

    #[test]
    fn test_sample_marked_positions_includes_required_positions() {
        let mut rng = OsRng;
        let config = BloomFilterConfig {
            bloom_filter_size: 32,
            hash_count: 3,
            target_marked_count: 8,
        };
        let required = vec![Scalar::from(2u64), Scalar::from(7u64), Scalar::from(19u64)];
        let marked_positions = sample_marked_positions(&mut rng, config, &required);

        for position in required {
            assert!(marked_positions.contains(&position));
        }
    }

    #[test]
    fn test_recommended_hash_count_tracks_bernoulli_density() {
        assert_eq!(recommended_hash_count(0.125), 3);
        assert_eq!(recommended_hash_count(0.25), 2);
        assert_eq!(recommended_hash_count(1.0), 1);
        assert_eq!(recommended_hash_count(0.0), 1);
    }
}
