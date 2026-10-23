#![cfg(test)]

use super::*;
use soroban_sdk::{vec, Bytes, BytesN, Env};

fn key(env: &Env) -> VerifyingKey {
    let g1 = BytesN::from_array(env, &[0; 64]);
    let g2 = BytesN::from_array(env, &[0; 128]);
    VerifyingKey {
        alpha: g1.clone(),
        beta: g2.clone(),
        gamma: g2.clone(),
        delta: g2,
        ic: vec![env, g1.clone(), g1],
    }
}

#[test]
fn rejects_malformed_proof_before_pairing() {
    let env = Env::default();
    let id = env.register(ShieldVerifier, (&key(&env),));
    let client = ShieldVerifierClient::new(&env, &id);
    assert!(!client.verify(&Bytes::new(&env), &vec![&env]));
}
