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
//! Honest validator zero-knowledge (HVZK): From an accepting transcript, we can simulate T_1, T_2, T_3 from totally random s_m, s_r, s_k <-$ Z_q and post hoc e, proving no aditional information is leaked.
//! Non-Interactive zero-knowledge (NIZK): Given by HVSK and the Fiat-Shamit heuristics.
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
//! Completeness, special soundness, HVZK and NIZK given by the Multi-relation Sigma Protocol with Fiat-Shamir heuristics.
//!
use curve25519_dalek::{
    RistrettoPoint, 
    Scalar,
    constants::RISTRETTO_BASEPOINT_POINT as G,
    traits::MultiscalarMul,
};
use rand_core::{OsRng, RngCore, CryptoRngCore};
use sha2::{Digest, Sha512};

static public_labels: &[&str] = &[
    "G",
    "H",
    "Y",
    "Cm",
    "C1",
    "C2",
    "T1",
    "T2",
    "T3",
];

/// Pedersen generator H from "hidden" label and Ristretto Base Point G.
fn pedersen_h() -> RistrettoPoint {
    let mut d = Sha512::new();
    d.update(b"Pedersen/H/domain_sep/v1");
    d.update(G.compress().as_bytes());
    RistrettoPoint::from_hash::<Sha512>(d)
}

/// Digest Helper for Scalar
fn absorb_scalar(label: &[u8], s: &Scalar, digest: &mut Sha512) {
    digest.update(label);
    digest.update(s.as_bytes());
}

/// Digest Helper for Ristretto Point
fn absorb_point(label: &[u8], p: &RistrettoPoint, digest: &mut Sha512) {
    digest.update(label);
    digest.update(p.compress().as_bytes())
}

#[derive(Clone)]
struct Message {
    pub m: Scalar,
    pub point: RistrettoPoint,
}

impl Message {
    pub fn new(s: &[u8]) -> Self {
        let m = Scalar::hash_from_bytes::<Sha512>(s);
        Self { m, point: m*G }
    }
}

#[derive(Clone, Debug)]
struct CipherText {
    pub c1: RistrettoPoint,
    pub c2: RistrettoPoint,
}

/// Twisted ElGamal Encryption
pub fn twisted_elgamal_encrypt<R: CryptoRngCore>(
    pk: &RistrettoPoint,
    msg: &RistrettoPoint,
    rng: &mut R,
) -> (CipherText, Scalar) {
    let k = Scalar::random(rng);
    let c1 = k*G;
    let c2 = msg + k*pk;
    (
        CipherText {c1, c2},
        k
    )
}

/// Twisted ElGamal Decryption
pub fn twisted_elgamal_decrypt(
    sk: &Scalar,
    ct: &CipherText,
) -> RistrettoPoint {
    let s = sk*ct.c1;
    ct.c2 - s
}

/// KeyPair openings
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct KeyPair {
    sk: Scalar,
    pub pk: RistrettoPoint,
}

impl KeyPair {
    pub fn generate() -> Self {
        let sk = Scalar::random(&mut OsRng);
        let pk = sk*G;
        Self { sk, pk }
    }
    pub fn get_secret(&self) -> Scalar {
        self.sk
    }
}

// ConsistencyProof is hiding and biding.
// Based on the discrete logarithm (DL) and the Discretional Diffie-Hellman (DDH) assumptions, this data is computationally hiding and binding to the witnesses m, r and k.
struct ConsistencyProof {
    Y: RistrettoPoint,
    cm: RistrettoPoint,
    c1: RistrettoPoint,
    c2: RistrettoPoint,
    t1: RistrettoPoint,
    t2: RistrettoPoint,
    t3: RistrettoPoint,
    s_m: Scalar,
    s_r: Scalar,
    s_k: Scalar,
}

fn check_challenge(value_list: &[(&str, RistrettoPoint)]) -> Sha512 {
    let mut e = Sha512::new();
    for (i, &(label, point)) in value_list.iter().enumerate() {
        if label == public_labels[i] {
            absorb_point(label.as_bytes(), &point,&mut  e);
        } else {
            panic!("Inconsistent Implementation") // it is Ok to panic if consistency must be enforced.
        }
    }
    e
}

impl ConsistencyProof {
    fn build<R: CryptoRngCore>(message: &Message, scheme: &ProtocolScheme, rng: &mut R) -> Self {
        let alpha = Scalar::random(rng);
        let beta = Scalar::random(rng);
        let gamma = Scalar::random(rng);
        let H = pedersen_h();
        let Y = scheme.Y;
        let cm = scheme.pedersen_commitment;
        let c1 = scheme.ct.c1;
        let c2 = scheme.ct.c2;
        let t1 = gamma*G;
        let t2 = alpha*G + gamma*Y;
        let t3 = alpha*G + beta*H;
        let challenge_values= [
            ("G", G),
            ("H", H),
            ("Y", Y),
            ("Cm", cm),
            ("C1", c1),
            ("C2", c2),
            ("T1", t1),
            ("T2", t2),
            ("T3", t3),
        ];
        let challenge_digest = check_challenge(&challenge_values);
        let e = Scalar::from_hash::<Sha512>(challenge_digest);

        // Responses
        let s_m = alpha + e * message.m;
        let s_r = beta  + e * scheme.r;
        let s_k = gamma + e * scheme.k;
        Self {
            Y,
            cm,
            c1,
            c2,
            t1,
            t2,
            t3,
            s_m,
            s_r,
            s_k,
        }
    }
    fn validate(&self) -> bool {
        let H = pedersen_h();
        let challenge_values= [
            ("G", G),
            ("H", H),
            ("Y", self.Y),
            ("Cm", self.cm),
            ("C1", self.c1),
            ("C2", self.c2),
            ("T1", self.t1),
            ("T2", self.t2),
            ("T3", self.t3),
        ];
        let challenge_digest = check_challenge(&challenge_values);
        let s_r = self.s_r;
        let s_m = self.s_m;
        let s_k = self.s_k;
        let e = Scalar::from_hash::<Sha512>(challenge_digest);
        self.s_k*G == self.t1 + e * self.c1
        && self.s_m*G + self.s_k*self.Y == self.t2 + e*self.c2
        && self.s_m*G + self.s_r*H == self.t3 + e*self.cm
    }
}

// ProtocolScheme contains the scheme construction from the perspective of the Prover
#[derive(Clone, Debug)]
pub struct ProtocolScheme {
    pub Y: RistrettoPoint,
    pub pedersen_commitment: RistrettoPoint,
    pub ct: CipherText,
    pub k: Scalar,
    pub r: Scalar,
}

impl ProtocolScheme {
    pub fn setup<R: CryptoRngCore>(message: &[u8], rng: &mut R) -> Self {
        let h = pedersen_h();
        let key_pair = KeyPair::generate();
        let message_opening = Message::new(message);
        let r = Scalar::random(rng);
        let encryption = twisted_elgamal_encrypt(&key_pair.pk, &message_opening.point, rng);
        let pedersen_commitment = RistrettoPoint::multiscalar_mul(&[message_opening.m, r], &[G, h]);
        Self {
            Y: key_pair.pk,
            pedersen_commitment,
            ct: encryption.0,
            k: encryption.1,
            r,
        }
    }
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
        absorb_scalar(b"Scalar label", &s, &mut d);
        absorb_point(b"Point label", &p, &mut d);
        let result = d.finalize();
        assert_eq!(result[..], [217, 227, 115, 4, 191, 27, 44, 136, 161, 244, 12, 207, 118, 146, 19, 87, 68, 41, 21, 139, 89, 140, 91, 220, 136, 119, 91, 94, 27, 149, 223, 82, 140, 40, 120, 224, 69, 131, 19, 157, 229, 88, 168, 207, 40, 32, 43, 25, 73, 174, 17, 98, 227, 38, 80, 169, 179, 200, 216, 41, 192, 112, 131, 243]);
    }
    
    #[test]
    fn generate_pair() {
        let pair_a = KeyPair::generate();
        let pair_b = KeyPair::generate();
        assert_ne!(pair_a.pk, pair_b.pk);
    }
    
    #[test]
    fn encrypt_decrypt_message() {
        let key_pair = KeyPair::generate();
        let message = Message::new(b"message to encrypt");
        let encrypted_message = twisted_elgamal_encrypt(&key_pair.pk, &message.point, &mut OsRng);
        let sk = key_pair.get_secret();
        let decrypted_message = twisted_elgamal_decrypt(&sk, &encrypted_message.0);
        assert_eq!(message.point, decrypted_message);
    }
    
    #[test]
    fn check_scheme() {
        // First message and scheme
        let plain_message = b"hidden message";
        let encoded_message = Message::new(plain_message);
        let scheme = ProtocolScheme::setup(plain_message, &mut OsRng);
        let proof_a = ConsistencyProof::build(&encoded_message, &scheme, &mut OsRng);
        // Second different message and scheme
        let another_message = b"another message";
        let another_encoded_message = Message::new(another_message);
        let another_scheme = ProtocolScheme::setup(another_message, &mut OsRng);
        let proof_b = ConsistencyProof::build(&another_encoded_message, &another_scheme, &mut OsRng);
        // crossed proofs
        let cross_proof_a = ConsistencyProof::build(&another_encoded_message, &scheme, &mut OsRng);
        let cross_proof_b = ConsistencyProof::build(&encoded_message, &another_scheme, &mut OsRng);
        assert!(proof_a.validate()); // valid encoding -> accept
        assert!(proof_b.validate()); // valid_encoding -> accept
        assert!(!cross_proof_a.validate()); // not valid encoding -> reject
        assert!(!cross_proof_b.validate()); // not valid encoding -> reject
    }
}
