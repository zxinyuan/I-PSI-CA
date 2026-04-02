//! I-PSI-CA demo: Target (TCP server) and Monitor (TCP client) 
//!
//! TSet and MElmt are uniformly random elements of 𝔽_ℓ, 
//! the scalar field of Ristretto255.
//!
//! Usage:
//!   cargo run -release          # random TSet, MElmt ∈ TSet  (match)
//!   cargo run -release -- false # random TSet, fresh random MElmt  (no match w.o.p.)

use std::thread;
use std::time::Duration;

use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;

use i_psi_ca::crypto::elgamal::generate_key_share;
use i_psi_ca::exact::monitor::Monitor;
use i_psi_ca::exact::target::Target;

const ADDR: &str = "127.0.0.1:7878";
const DEGREE: usize = 1_000;

fn main() {
    // Parse optional CLI arg
    let args: Vec<String> = std::env::args().collect();
    let in_set: bool = match args.as_slice() {
        [_, flag] => flag.parse().expect("arg must be true/false"),
        _         => true,
    };

    let mut rng = OsRng;

    // Sample TSet: DEGREE independent uniform random field elements
    // Field: 𝔽_ℓ, ℓ = 2^252 + 27742317777372353535851937790883648493 (Ristretto255 group order)
    let t_set: Vec<Scalar> = (0..DEGREE).map(|_| Scalar::random(&mut rng)).collect();

    // Sample MElmt
    // Match:    pick an element already in TSet.
    // No match: fresh uniform random element — collision probability ≈ DEGREE/ℓ
    let m_elmt: Scalar = if in_set {
        t_set[0]
    } else {
        Scalar::random(&mut rng)
    };

    println!("TSet        = [{}  uniform random 𝔽_ℓ elements]", DEGREE);
    println!("MElmt       = uniform random 𝔽_ℓ element  (in_set={in_set})");
    println!("Expected    = {}", if in_set { "MATCH" } else { "NO MATCH" });
    println!();

    // Key generation (shared setup for simplicity)
    let (sk1, pk1) = generate_key_share(&mut rng);
    let (sk2, pk2) = generate_key_share(&mut rng);

    let set_size = t_set.len();
    let pk2_for_target  = pk2.clone();
    let pk1_for_monitor = pk1.clone();

    // Spawn TCP
    let target_handle = thread::spawn(move || {
        let mut target = Target::new(t_set, sk1, pk1, pk2_for_target);
        target.run(ADDR).expect("[Target] server error");
        println!("[Target] Final match count: {}", target.state);
    });

    thread::sleep(Duration::from_millis(50));

    let monitor = Monitor::new(m_elmt, sk2, pk1_for_monitor, pk2, set_size);
    monitor.run(ADDR, 1 /* rounds */).expect("[Monitor] client error");

    target_handle.join().expect("Target thread panicked");
}
