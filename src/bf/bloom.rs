use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;
use rand::Rng;

#[derive(Clone, Copy, Debug)]
pub struct BloomFilterConfig {
    pub bloom_filter_size: usize,
    pub hash_count: usize,
    pub honeyword_probability: f64,
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
        if !(0.0..=1.0).contains(&self.honeyword_probability) {
            return Err("honeyword probability p_h must be in [0, 1]".to_string());
        }
        Ok(self)
    }

    pub fn bit_density(self) -> f64 {
        self.honeyword_probability.powf(1.0 / self.hash_count as f64)
    }

    pub fn target_marked_count(self) -> usize {
        let raw = (self.bit_density() * self.bloom_filter_size as f64).round() as usize;
        raw.clamp(0, self.bloom_filter_size)
    }
}

pub fn scalar_positions(input: Scalar, config: BloomFilterConfig) -> Vec<Scalar> {
    let base = scalar_to_usize(input);
    let usable_span = config.bloom_filter_size - config.hash_count + 1;
    assert!(
        (1..=usable_span).contains(&base),
        "input scalar must lie in the supported Bloom-hash domain"
    );
    let start = base;
    (0..config.hash_count)
        .map(|offset| Scalar::from((start + offset) as u64))
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
    let target_count = config.target_marked_count().max(marked_positions.len());
    if target_count == marked_positions.len() {
        return marked_positions;
    }

    universe.retain(|position| !marked_positions.contains(position));
    for i in (1..universe.len()).rev() {
        let j = rng.gen_range(0..=i);
        universe.swap(i, j);
    }

    marked_positions.extend(universe.into_iter().take(target_count - marked_positions.len()));
    marked_positions
}

pub fn scalar_is_member(
    input: Scalar,
    marked_positions: &[Scalar],
    config: BloomFilterConfig,
) -> bool {
    scalar_positions(input, config)
        .into_iter()
        .all(|position| marked_positions.contains(&position))
}

pub fn find_non_member_scalar(
    marked_positions: &[Scalar],
    config: BloomFilterConfig,
) -> Option<Scalar> {
    if config.honeyword_probability == 1.0 {
        return None;
    }

    let usable_span = config.bloom_filter_size - config.hash_count + 1;
    for candidate in 1..=usable_span as u64 {
        let candidate = Scalar::from(candidate);
        if !scalar_is_member(candidate, marked_positions, config) {
            return Some(candidate);
        }
    }

    None
}

pub fn dedup_positions(positions: &[Scalar]) -> Vec<Scalar> {
    let mut deduped = Vec::new();
    for position in positions {
        if !deduped.contains(position) {
            deduped.push(*position);
        }
    }
    deduped
}

pub fn sample_query_scalar<R: Rng + ?Sized>(rng: &mut R, config: BloomFilterConfig) -> Scalar {
    let usable_span = config.bloom_filter_size - config.hash_count + 1;
    Scalar::from(rng.gen_range(1..=usable_span as u64))
}

pub fn hash_offset(hash_index: usize) -> Scalar {
    Scalar::from((hash_index + 1) as u64)
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
            honeyword_probability: 0.25,
        };
        let positions = scalar_positions(Scalar::from(3u64), config);
        assert_eq!(positions.len(), 3);
        assert_eq!(
            positions,
            vec![Scalar::from(3u64), Scalar::from(4u64), Scalar::from(5u64)]
        );
    }

    #[test]
    fn test_sample_marked_positions_includes_required_positions() {
        let mut rng = OsRng;
        let config = BloomFilterConfig {
            bloom_filter_size: 32,
            hash_count: 3,
            honeyword_probability: 0.125,
        };
        let required = vec![Scalar::from(2u64), Scalar::from(7u64), Scalar::from(19u64)];
        let marked_positions = sample_marked_positions(&mut rng, config, &required);

        for position in required {
            assert!(marked_positions.contains(&position));
        }
    }
}
