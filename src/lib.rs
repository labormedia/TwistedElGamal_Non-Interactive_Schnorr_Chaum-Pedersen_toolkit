//! Twisted ElGamal Non-Interactive Chaum/Pedersen protocol
//! Consider cyclic Group (|G, +) of prime order q with generator G and H with fixed and secret domain separator (hidden dependence).
//! For Key Generation x <-$ Z_q, Y = x*G,
//! With message in scalar form m, it encodes M = m*G in |G.
//!
//! Encryption is as follows:
//! k <-$ Z_q, 
//! C_1 = k*G, C_2 = M + k*Y
//! Ciphertext CT = (C_1, C_2)
//!
//! Decryption:
//! Compute S' = x*C_1 = x*k*G = k*x*G = k*Y
//! C_2 - S' = M + k*Y - k*Y = M = m*G
//! Then solves the discrete logarithm (theoretical) of M = m*G to recover m
//!
//! Goal:
//! Given a Public Key, a Commitment and a Ciphertext prove:
//! There exist scalars m, r and k such that:
//! C_m = m*G + r*H, C_1 = k*G, C_2 = M + k*Y  // This statement hides M = m*G with domain separated H and randomly generated r, while encrypting the same original m of the message.
//! 
//! Statement and witnesses:
//! Public: G, H, Y, C_m, C_1, C_2
//! Witnesses: m, r, k in Z_q
//!
//! C_m = m*G + r*H
//! C_1 = k*G
//! C_2 = M + k*Y
//!
//! Multi-relation Sigma Protocol (P, V):
//! Prover P chooses random alpha, beta, gamma <-$ Z_q
//! and defines:
//! T_1 = gamma*G
//! T_2 = alpha*G + gamma*Y
//! T_3 = alpha*G + beta*H
//!
//! Computes Fiat-Shamir challenge for the Non-Interactive construction:
//! e = Hash(G, H, Y, C_m, C_1, C_2, T_1, T_2, T_3)
//! 
//! and responds with scalars:
//! s_m = alpha + e*m, s_r = beta + e*r, s_k = gamma + e*k
//! 
//! Validator V checks:
//! s_k*G =? T_1 + e*C_1
//! s_m*G + s_k*Y =? T_2 + e*C_2
//! s_m*G + S_r*H =? T_3 + e*C_m
//! and accepts if they all hold, otherwise it rejects
//!
//! Properties:
//! Completeness: check for generic variables
//! Special soundness: Two accepting transcripts with same initial T_1, T_2, T_3 and different challenges extracts the openings (m, r, k)
//! Honest validator zero-knowledge (HVSK): From an accepting transcript, we can simulate T_1, T_2, T_3 from totally random s_m, s_r, s_k <-$ Z_q and post hoc e, proving no aditional information is leaked.
//! Non-Interactive zero-knowledge (NISK): Given by HVSK and the Fiat-Shamit heuristics.
//!
//! Sigma Protocol (P,V) for Verifiable Decryption (Chaum-Pedersen):
//! Proves that log_G(C1) = log_Y(C2 - M)
//! 
//! -> Prover P choose t <-$ Z_q and sends:
//! A = t*G, B = t*Y
//! <- Validator V send a challenge e
//! -> Prover responds with scalar z = t + e*k
//! V verifies z*G =? A + e*C_1, z*Y =? B + (C_2 - M)
//! If both conditions hold, accepts, otherwise rejects.
//!
//! Completeness, special soundness, HVSK and NISK given by the Multi-relation Sigma Protocol with Fiat-Shamir heuristics.
//!
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

fn absorb_scalar(s: &Scalar, digest: &mut Sha512) {
    digest.update(s.as_bytes());
}

fn absorb_point(p: &RistrettoPoint, digest: &mut Sha512) {
    digest.update(p.compress().as_bytes())
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

    #[test]
    fn absorb_digest() {
        let mut d = Sha512::new();
        let s = Scalar::hash_from_bytes::<Sha512>(b"Byte phrase for scalar");
        let p = RistrettoPoint::hash_from_bytes::<Sha512>(b"Byte phrase for point");
        absorb_scalar(&s, &mut d);
        absorb_point(&p, &mut d);
        let result = d.finalize();
        assert_eq!(result[..], [51, 50, 172, 159, 80, 179, 20, 36, 74, 141, 221, 10, 148, 49, 202, 164, 105, 244, 20, 193, 89, 165, 87, 224, 128, 77, 128, 234, 9, 245, 255, 131, 241, 249, 193, 56, 177, 67, 82, 20, 54, 14, 112, 75, 173, 56, 75, 104, 215, 77, 36, 219, 205, 252, 77, 254, 135, 214, 156, 229, 156, 137, 217, 153]);
    }
}
