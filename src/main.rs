use ark_bls12_381::{g2::Config, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    AffineRepr, CurveGroup,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::*;
use ark_serialize::{CanonicalDeserialize, Read};

use prompt::{puzzle, welcome};

use sha2::Sha256;
use std::io::Cursor;
use std::ops::{Mul, Neg};
use std::{fs::File, ops::Sub};

use ark_std::{rand::SeedableRng, UniformRand, Zero};

fn derive_point_for_pok(i: usize) -> G2Affine {
    let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(20399u64);
    G2Affine::rand(rng).mul(Fr::from(i as u64 + 1)).into()
}

#[allow(dead_code)]
fn pok_prove(sk: Fr, i: usize) -> G2Affine {
    derive_point_for_pok(i).mul(sk).into()
}

fn pok_verify(pk: G1Affine, i: usize, proof: G2Affine) {
    assert!(Bls12_381::multi_pairing(
        &[pk, G1Affine::generator()],
        &[derive_point_for_pok(i).neg(), proof]
    )
    .is_zero());
}

fn hasher() -> MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Config>> {
    let wb_to_curve_hasher =
        MapToCurveBasedHasher::<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Config>>::new(
            &[1, 3, 3, 7],
        )
        .unwrap();
    wb_to_curve_hasher
}

#[allow(dead_code)]
fn bls_sign(sk: Fr, msg: &[u8]) -> G2Affine {
    hasher().hash(msg).unwrap().mul(sk).into_affine()
}

fn bls_verify(pk: G1Affine, sig: G2Affine, msg: &[u8]) {
    assert!(Bls12_381::multi_pairing(
        &[pk, G1Affine::generator()],
        &[hasher().hash(msg).unwrap().neg(), sig]
    )
    .is_zero());
}

fn from_file<T: CanonicalDeserialize>(path: &str) -> T {
    let mut file = File::open(path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    T::deserialize_uncompressed_unchecked(Cursor::new(&buffer)).unwrap()
}

fn main() {
    welcome();
    puzzle(PUZZLE_DESCRIPTION);

    let public_keys: Vec<(G1Affine, G2Affine)> = from_file("public_keys.bin");

    public_keys
        .iter()
        .enumerate()
        .for_each(|(i, (pk, proof))| pok_verify(*pk, i, *proof));

    let new_key_index = public_keys.len();
    let message = b"4rgon4ut";

    /* Enter solution here */

    let new_secret: Fr = Fr::zero();

    let honest_aggregated_pk = public_keys
        .iter()
        .fold(G1Projective::zero(), |acc, (pk, _)| acc + pk);

    /*
        As stated in rogue key attack description, we can use the fact that the aggregated public key
        is a linear combination of the honest public keys to compute the new key that will negate all
        honest keys contributions.
        As sk = 0 => pk = O (point at infinity)
        Thus we can compute honest keys aggregation inverse as follows:
    */
    let new_key = G1Affine::generator()
        .mul(new_secret) // pk = g^sk
        .sub(honest_aggregated_pk.clone()) // find point that negates all honest keys
        .into_affine();

    /*
        Now we have pk which is an inverse of honest keys sum
        => sk of our negating pk (new_key) should be an inverse on g^sk1+g^sk2+...+g^skn
        As we have list of proofs for those honest sks, where every proof is:
        proof_i = r^i+1^sk_i     (note that rng result is always the same becouse of seeding, we can denote it as 'r')
        Than our proof for new_key should be:
        new_proof = r^new_key_index^(sk1+sk2+...+skn)^-1 where (sk1+sk2+...+skn)^-1 is inverse of sum of all honest sks

        To get those sum of honest sks we should clear proofs from index factors and sum them up:
        sum_of_honest_sks = sum(proof_i^(-1 * i+1))

        Than multiply those sum by new_key_index by new_key_index and negate it to get new_proof:
    */
    let new_proof = public_keys
        .iter()
        .enumerate()
        .fold(G2Projective::zero(), |acc, (i, (_, proof))| {
            let inverse_factor = Fr::from(i as u64 + 1).inverse().unwrap();
            acc + proof.mul(inverse_factor) // clear idx factor
        })
        .mul(Fr::from(new_key_index as u64 + 1)) // multiply by new_key_index to follow proof generation
        .neg()
        .into_affine();

    let aggregate_signature = bls_sign(new_secret, message);

    /* End of solution */

    pok_verify(new_key, new_key_index, new_proof);
    let aggregate_key = public_keys
        .iter()
        .fold(G1Projective::from(new_key), |acc, (pk, _)| acc + pk)
        .into_affine();
    bls_verify(aggregate_key, aggregate_signature, message)
}

const PUZZLE_DESCRIPTION: &str = r"
Bob has been designing a new optimized signature scheme for his L1 based on BLS signatures. Specifically, he wanted to be able to use the most efficient form of BLS signature aggregation, where you just add the signatures together rather than having to delinearize them. In order to do that, he designed a proof-of-possession scheme based on the B-KEA assumption he found in the the Sapling security analysis paper by Mary Maller [1]. Based the reasoning in the Power of Proofs-of-Possession paper [2], he concluded that his scheme would be secure. After he deployed the protocol, he found it was attacked and there was a malicious block entered the system, fooling all the light nodes...

[1] https://github.com/zcash/sapling-security-analysis/blob/master/MaryMallerUpdated.pdf
[2] https://rist.tech.cornell.edu/papers/pkreg.pdf
";
