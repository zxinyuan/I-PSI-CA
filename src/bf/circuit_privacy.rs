//! BFV terminal circuit-privacy transformation and conservative parameter budget.
//! Implements rerandomize, then a *single exact coefficient-wise floor division*
//! as in de Castro/Juvekar/Vaikuntanathan, ePrint 2020/685, Algorithm 1.
//! Security is conditional on honest/bounded keys and fresh bounded source CTs;
//! parsing a ciphertext or a public key does not establish those conditions.
use fhe::bfv::{BfvParameters, Ciphertext};
use fhe_math::rq::{traits::TryConvertFrom, Poly, Representation};
use num_bigint::BigUint;
use std::sync::Arc;

pub const STATISTICAL_BITS: usize = 128;
pub(crate) const RETAINED_LIMBS: usize = 2;
// Explicitly set in our parameter builder; CBD variance v has support [-2v,2v].
pub(crate) const ERROR_VARIANCE: usize = 10;

/// Exact conservative bounds, with no measured-noise input or floating point.
/// One budget covers all three independent membership ciphertexts in a report.
pub struct PrivacyBudget {
    pub evaluated_noise_bound: BigUint,
    pub fresh_zero_noise_bound: BigUint,
    pub divisor: BigUint,
    pub retained_modulus: BigUint,
    pub statistical_bits: usize,
    pub max_coefficients: usize,
}

impl PrivacyBudget {
    pub(crate) fn calculate(
        degree: usize,
        plaintext: u64,
        moduli: &[u64],
        max_coefficients: usize,
        repetitions: usize,
    ) -> Result<Self, String> {
        Self::calculate_inner(
            degree,
            plaintext,
            moduli,
            max_coefficients,
            repetitions,
            true,
        )
    }
    pub(crate) fn calculate_sampled(
        degree: usize,
        plaintext: u64,
        moduli: &[u64],
        max_coefficients: usize,
        repetitions: usize,
    ) -> Result<Self, String> {
        Self::calculate_inner(
            degree,
            plaintext,
            moduli,
            max_coefficients,
            repetitions,
            false,
        )
    }
    fn calculate_inner(
        degree: usize,
        plaintext: u64,
        moduli: &[u64],
        max_coefficients: usize,
        repetitions: usize,
        trace: bool,
    ) -> Result<Self, String> {
        if !degree.is_power_of_two()
            || degree < 2
            || plaintext < 2
            || moduli.len() <= RETAINED_LIMBS
            || max_coefficients == 0
            || repetitions == 0
        {
            return Err("invalid circuit-privacy parameters".into());
        }
        let n = BigUint::from(degree);
        let t = BigUint::from(plaintext);
        let b = BigUint::from(2 * ERROR_VARIANCE);
        let one = BigUint::from(1u8);
        // pk = (-a*s+e,a); fresh public encryption has e*u+e0+e1*s.
        // Ring expansion ||uv||_inf <= N ||u||_inf ||v||_inf.
        let fresh = BigUint::from(2u8) * &n * &b * &b + &b;
        let blocks = max_coefficients.div_ceil(degree);
        // Work relative to the rational encoding Q*m/t. The library's
        // coefficient-wise floor encoding differs by <1, so plaintext products
        // cost at most N*(t-1)*(fresh+1) per block, including zero padding.
        let product_noise = BigUint::from(blocks) * &n * (&t - &one) * (&fresh + &one);
        // RNS key switching uses one coefficient-bounded digit d_i in [0,q_i)
        // per limb. Its error sum is sum_i d_i*e_i.
        let digit_sum: BigUint = moduli.iter().map(|&q| BigUint::from(q - 1)).sum();
        let key_switch_noise = &n * &b * digit_sum;
        // Inner sum performs log2(N) automorphism/add steps. At each step:
        // B_next <= 2 B + K. Thus B_trace <= N B + (N-1) K.
        // Convert the rational encoding to the paper's floor(Q/t)*m encoding:
        // the additional coefficient error is <t (not a measured bound).
        let evaluated = if trace {
            &n * product_noise + (&n - &one) * key_switch_noise + &t
        } else {
            product_noise + &t
        };
        let retained: BigUint = moduli[..RETAINED_LIMBS]
            .iter()
            .map(|&q| BigUint::from(q))
            .product();
        let divisor: BigUint = moduli[RETAINED_LIMBS..]
            .iter()
            .map(|&q| BigUint::from(q))
            .product();
        // Union bound over coefficients AND all membership repetitions.
        let bad_numerator = BigUint::from(2 * repetitions) * &n * (&evaluated + &fresh);
        if (&bad_numerator << STATISTICAL_BITS) > divisor {
            return Err("insufficient modulus gap for 128-bit circuit-privacy budget".into());
        }
        // Floor division creates component rounding errors <1. Combining the
        // two components under a secret bounded by b costs at most 1+N*b;
        // plaintext rescaling/encoding costs another t+2, conservatively.
        let rounded_noise =
            &n * &b + &t + BigUint::from(2u8) + (&evaluated + &fresh).div_ceil(&divisor);
        if BigUint::from(2u8) * &t * rounded_noise >= retained {
            return Err("insufficient final modulus for correct decryption".into());
        }
        Ok(Self {
            evaluated_noise_bound: evaluated,
            fresh_zero_noise_bound: fresh,
            divisor,
            retained_modulus: retained,
            statistical_bits: STATISTICAL_BITS,
            max_coefficients,
        })
    }
}

/// Exact floor, not sequential round-to-nearest modulus switching. Reuses the
/// library's CRT lift and ring conversions; no custom NTT or CRT arithmetic.
pub(crate) fn divide_and_floor(
    ct: &Ciphertext,
    parameters: &Arc<BfvParameters>,
    retained_limbs: usize,
) -> Result<Ciphertext, String> {
    let moduli = parameters.moduli();
    if ct.len() != 2
        || retained_limbs == 0
        || retained_limbs >= moduli.len()
        || ct[0].ctx() != parameters.context_at_level(0).map_err(|e| e.to_string())?
    {
        return Err("invalid input to terminal divide-and-floor".into());
    }
    let divisor: BigUint = moduli[retained_limbs..]
        .iter()
        .map(|&q| BigUint::from(q))
        .product();
    let destination = parameters
        .context_at_level(moduli.len() - retained_limbs)
        .map_err(|e| e.to_string())?;
    let mut components = Vec::with_capacity(2);
    for component in ct.iter() {
        let mut power = component.clone();
        power.change_representation(Representation::PowerBasis);
        let lifted = Vec::<BigUint>::from(&power);
        let quotient = lifted.into_iter().map(|x| x / &divisor).collect::<Vec<_>>();
        let mut polynomial = Poly::try_convert_from(
            quotient.as_slice(),
            destination,
            false,
            Representation::PowerBasis,
        )
        .map_err(|e| e.to_string())?;
        polynomial.change_representation(Representation::Ntt);
        components.push(polynomial);
    }
    Ciphertext::new(components, parameters).map_err(|e| e.to_string())
}

// Avoid adding num-integer merely for one positive-integer ceiling division.
trait CeilDiv {
    fn div_ceil(&self, rhs: &Self) -> Self;
}
impl CeilDiv for BigUint {
    fn div_ceil(&self, rhs: &Self) -> Self {
        (self + rhs - BigUint::from(1u8)) / rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext, PublicKey, SecretKey};
    use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};

    #[test]
    fn exact_floor_preserves_full_plaintexts_and_rejects_wrong_levels() {
        let parameters = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus(17)
            .set_moduli_sizes(&[30, 30, 30])
            .build_arc()
            .unwrap();
        let mut rng = rand09::rng();
        let sk = SecretKey::random(&parameters, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);
        for values in [vec![0; 16], vec![16; 16], (0..16).collect::<Vec<_>>()] {
            let pt = Plaintext::try_encode(&values, Encoding::poly(), &parameters).unwrap();
            let ct = pk.try_encrypt(&pt, &mut rng).unwrap();
            let quotient = divide_and_floor(&ct, &parameters, 2).unwrap();
            let decoded =
                Vec::<u64>::try_decode(&sk.try_decrypt(&quotient).unwrap(), Encoding::poly())
                    .unwrap();
            assert_eq!(decoded, values);
            assert!(divide_and_floor(&quotient, &parameters, 2).is_err());
        }
    }
    #[test]
    fn refuses_current_profiles_and_accepts_the_larger_gap() {
        // Near-maximum 62-bit limbs match the builder's generated-prime sizes.
        assert!(PrivacyBudget::calculate(
            8192,
            2_305_843_009_211_596_801,
            &[(1 << 61) + 1; 3],
            1 << 20,
            3
        )
        .is_err());
        let budget = PrivacyBudget::calculate(
            16384,
            2_305_843_009_211_596_801,
            &[(1 << 62) - 1; 7],
            1 << 20,
            3,
        )
        .unwrap();
        assert_eq!(budget.statistical_bits, 128);
        assert!(budget.evaluated_noise_bound.bits() < 125);
        assert!(PrivacyBudget::calculate(
            16384,
            2_305_843_009_211_596_801,
            &[(1 << 61) + 1; 6],
            1 << 20,
            3
        )
        .is_err());
    }
}
