use curve25519_dalek::{
    RistrettoPoint, 
    Scalar,
    constants::RISTRETTO_BASEPOINT_POINT as G,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha512};

fn pedersen_h() -> RistrettoPoint {
    let mut d = Sha512::new();
    d.update(b"Pedersen/H/domain_sep/v1");
    d.update(G.compress().as_bytes());
    RistrettoPoint::from_hash::<Sha512>(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng() {
        let i: u32 = OsRng.next_u32();
        let j: u32 = OsRng.next_u32();
        assert_ne!(i, j);
    }
    
    #[test]
    fn pedersen_h_separator() {
        let a = pedersen_h();
        let b = pedersen_h();
        assert_eq!(a, b);
    }
}
