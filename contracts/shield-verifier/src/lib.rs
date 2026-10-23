#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr},
    Bytes, BytesN, Env, Vec,
};

const SCALAR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Groth16 verification key in Soroban's Ethereum-compatible BN254 encodings.
/// `ic` is the constant point followed by one point per public input.
#[contracttype]
#[derive(Clone)]
pub struct VerifyingKey {
    pub alpha: BytesN<64>,
    pub beta: BytesN<128>,
    pub gamma: BytesN<128>,
    pub delta: BytesN<128>,
    pub ic: Vec<BytesN<64>>,
}

#[contracttype]
pub enum DataKey {
    VerifyingKey,
}

#[contract]
pub struct ShieldVerifier;

#[contractimpl]
impl ShieldVerifier {
    pub fn __constructor(env: Env, verifying_key: VerifyingKey) {
        env.storage()
            .instance()
            .set(&DataKey::VerifyingKey, &verifying_key);
    }

    pub fn verify(env: Env, proof: Bytes, inputs: Vec<BytesN<32>>) -> bool {
        if proof.len() != 256 {
            return false;
        }

        let vk: VerifyingKey = env
            .storage()
            .instance()
            .get(&DataKey::VerifyingKey)
            .unwrap();
        if vk.ic.len() != inputs.len() + 1 {
            return false;
        }

        let mut vk_x = g1(vk.ic.get(0).unwrap());
        for i in 0..inputs.len() {
            let input = inputs.get(i).unwrap();
            if input.to_array() >= SCALAR_MODULUS {
                return false;
            }
            let term = env
                .crypto()
                .bn254()
                .g1_mul(&g1(vk.ic.get(i + 1).unwrap()), &Fr::from_bytes(input));
            vk_x = env.crypto().bn254().g1_add(&vk_x, &term);
        }

        let mut g1s = Vec::new(&env);
        g1s.push_back(-g1_at(&env, &proof, 0));
        g1s.push_back(g1(vk.alpha));
        g1s.push_back(vk_x);
        g1s.push_back(g1_at(&env, &proof, 192));
        let mut g2s = Vec::new(&env);
        g2s.push_back(g2_at(&env, &proof, 64));
        g2s.push_back(g2(vk.beta));
        g2s.push_back(g2(vk.gamma));
        g2s.push_back(g2(vk.delta));
        env.crypto().bn254().pairing_check(g1s, g2s)
    }
}

fn g1(bytes: BytesN<64>) -> Bn254G1Affine {
    Bn254G1Affine::from_bytes(bytes)
}

fn g2(bytes: BytesN<128>) -> Bn254G2Affine {
    Bn254G2Affine::from_bytes(bytes)
}

fn g1_at(env: &Env, proof: &Bytes, start: u32) -> Bn254G1Affine {
    let mut out = [0u8; 64];
    proof.slice(start..start + 64).copy_into_slice(&mut out);
    g1(BytesN::from_array(env, &out))
}

fn g2_at(env: &Env, proof: &Bytes, start: u32) -> Bn254G2Affine {
    let mut out = [0u8; 128];
    proof.slice(start..start + 128).copy_into_slice(&mut out);
    g2(BytesN::from_array(env, &out))
}

mod test;
