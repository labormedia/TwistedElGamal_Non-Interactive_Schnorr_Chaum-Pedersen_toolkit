use curve25519_dalek::{RistrettoPoint, Scalar};

type CypherText = (RistrettoPoint, RistrettoPoint);

trait Commit {
    fn commit(x: Scalar, r: Scalar) -> RistrettoPoint;
}

trait Encryption {
    fn keygen() -> (RistrettoPoint, Scalar);
    fn encrypt(pk: RistrettoPoint, x: Scalar) -> CypherText;
    fn decrypt(sk: Scalar, ct: CypherText) -> Scalar;
}