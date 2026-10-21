#![cfg(test)]
//! Tests for ShieldVault withdrawals, nullifier tracking and replay protection.
//! Proof verification is mocked: real Groth16 proofs are wired in during Phase 2.

use super::*;
use soroban_sdk::{
    contract, contractimpl, symbol_short,
    testutils::{Address as _, Events as _},
    token::{StellarAssetClient, TokenClient},
    vec, Address, Bytes, BytesN, Env, Event, Vec,
};

// ---------------------------------------------------------------------------
// Mock verifier: returns a configurable result and records the public inputs
// it was called with, so tests can check the vault's input ordering.
// ---------------------------------------------------------------------------

#[contract]
pub struct MockVerifier;

#[contractimpl]
impl MockVerifier {
    /// Sets the result that `verify` will return.
    pub fn set_result(env: Env, result: bool) {
        env.storage()
            .instance()
            .set(&symbol_short!("result"), &result);
    }

    /// Returns the public inputs from the most recent `verify` call.
    pub fn last_inputs(env: Env) -> Vec<BytesN<32>> {
        env.storage()
            .instance()
            .get(&symbol_short!("inputs"))
            .unwrap()
    }

    pub fn verify(env: Env, _proof: Bytes, public_inputs: Vec<BytesN<32>>) -> bool {
        env.storage()
            .instance()
            .set(&symbol_short!("inputs"), &public_inputs);
        env.storage()
            .instance()
            .get(&symbol_short!("result"))
            .unwrap_or(true)
    }
}

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

const BATCH_ID: u64 = 1;
const BATCH_TOTAL: i128 = 10_000;

struct Setup<'a> {
    env: Env,
    vault: ShieldVaultClient<'a>,
    verifier: MockVerifierClient<'a>,
    token: TokenClient<'a>,
    root: BytesN<32>,
}

/// Deploys a vault with a mock verifier and a funded batch of BATCH_TOTAL tokens.
///
/// The batch is written straight into storage because batch registration is
/// Person 1's function and not implemented yet.
fn setup<'a>() -> Setup<'a> {
    let env = Env::default();
    env.mock_all_auths();

    let verifier_id = env.register(MockVerifier, ());
    let vault_id = env.register(ShieldVault, (&verifier_id,));

    let admin = Address::generate(&env);
    let token_id = env.register_stellar_asset_contract_v2(admin).address();
    StellarAssetClient::new(&env, &token_id).mint(&vault_id, &BATCH_TOTAL);

    let root = BytesN::from_array(&env, &[7u8; 32]);
    let batch = Batch {
        root: root.clone(),
        token: token_id.clone(),
        total: BATCH_TOTAL,
        withdrawn: 0,
    };
    env.as_contract(&vault_id, || {
        env.storage()
            .persistent()
            .set(&DataKey::Batch(BATCH_ID), &batch);
    });

    Setup {
        vault: ShieldVaultClient::new(&env, &vault_id),
        verifier: MockVerifierClient::new(&env, &verifier_id),
        token: TokenClient::new(&env, &token_id),
        root,
        env,
    }
}

/// A small, canonical test nullifier: the field element `n`.
fn nullifier(env: &Env, n: u8) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[31] = n;
    BytesN::from_array(env, &bytes)
}

/// Placeholder proof bytes; the mock verifier ignores them.
fn proof(env: &Env) -> Bytes {
    Bytes::from_array(env, &[1u8; 256])
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[test]
fn withdraw_pays_recipient_and_marks_nullifier() {
    let s = setup();
    let recipient = Address::generate(&s.env);
    let n = nullifier(&s.env, 1);

    s.vault
        .withdraw(&BATCH_ID, &proof(&s.env), &n, &recipient, &2_500);

    assert_eq!(s.token.balance(&recipient), 2_500);
    assert_eq!(s.token.balance(&s.vault.address), BATCH_TOTAL - 2_500);
    assert!(s.vault.is_nullifier_used(&BATCH_ID, &n));
    assert_eq!(s.vault.get_batch(&BATCH_ID).unwrap().withdrawn, 2_500);
}

#[test]
fn withdraw_passes_public_inputs_in_circuit_order() {
    let s = setup();
    let recipient = Address::generate(&s.env);
    let n = nullifier(&s.env, 1);

    s.vault
        .withdraw(&BATCH_ID, &proof(&s.env), &n, &recipient, &2_500);

    // [root, nullifierHash, recipient, amount]
    let mut amount = [0u8; 32];
    amount[30..].copy_from_slice(&2_500u16.to_be_bytes());
    let expected = vec![
        &s.env,
        s.root.clone(),
        n,
        recipient_to_field(&s.env, &recipient),
        BytesN::from_array(&s.env, &amount),
    ];
    assert_eq!(s.verifier.last_inputs(), expected);
}

#[test]
fn withdraw_emits_event() {
    let s = setup();
    let recipient = Address::generate(&s.env);
    let n = nullifier(&s.env, 1);

    s.vault
        .withdraw(&BATCH_ID, &proof(&s.env), &n, &recipient, &2_500);

    let event = Withdrawn {
        batch_id: BATCH_ID,
        nullifier: n,
        recipient,
        amount: 2_500,
    };
    assert_eq!(
        s.env.events().all().filter_by_contract(&s.vault.address),
        [Event::to_xdr(&event, &s.env, &s.vault.address)]
    );
}

#[test]
fn whole_batch_can_be_withdrawn_exactly() {
    let s = setup();
    for (i, amount) in [6_000i128, 4_000].iter().enumerate() {
        let recipient = Address::generate(&s.env);
        s.vault.withdraw(
            &BATCH_ID,
            &proof(&s.env),
            &nullifier(&s.env, i as u8 + 1),
            &recipient,
            amount,
        );
    }
    let batch = s.vault.get_batch(&BATCH_ID).unwrap();
    assert_eq!(batch.withdrawn, batch.total);
    assert_eq!(s.token.balance(&s.vault.address), 0);
}

// ---------------------------------------------------------------------------
// Double claims and replays
// ---------------------------------------------------------------------------

#[test]
fn double_claim_with_same_nullifier_is_rejected() {
    let s = setup();
    let recipient = Address::generate(&s.env);
    let n = nullifier(&s.env, 1);

    s.vault
        .withdraw(&BATCH_ID, &proof(&s.env), &n, &recipient, &2_500);
    let result = s
        .vault
        .try_withdraw(&BATCH_ID, &proof(&s.env), &n, &recipient, &2_500);

    assert_eq!(result, Err(Ok(VaultError::NullifierUsed)));
    assert_eq!(s.token.balance(&recipient), 2_500);
}

#[test]
fn replayed_nullifier_to_a_different_recipient_is_rejected() {
    let s = setup();
    let n = nullifier(&s.env, 1);

    s.vault.withdraw(
        &BATCH_ID,
        &proof(&s.env),
        &n,
        &Address::generate(&s.env),
        &2_500,
    );
    let attacker = Address::generate(&s.env);
    let result = s
        .vault
        .try_withdraw(&BATCH_ID, &proof(&s.env), &n, &attacker, &2_500);

    assert_eq!(result, Err(Ok(VaultError::NullifierUsed)));
    assert_eq!(s.token.balance(&attacker), 0);
}

#[test]
fn non_canonical_nullifier_is_rejected() {
    // n + r would verify like n in many verifiers but is a different storage key
    let s = setup();
    let at_modulus = BytesN::from_array(&s.env, &FIELD_MODULUS);
    let above = BytesN::from_array(&s.env, &[0xff; 32]);

    for n in [at_modulus, above] {
        let result = s.vault.try_withdraw(
            &BATCH_ID,
            &proof(&s.env),
            &n,
            &Address::generate(&s.env),
            &2_500,
        );
        assert_eq!(result, Err(Ok(VaultError::NonCanonicalNullifier)));
    }
}

#[test]
fn nullifiers_are_scoped_per_batch() {
    let s = setup();
    let n = nullifier(&s.env, 1);
    s.vault.withdraw(
        &BATCH_ID,
        &proof(&s.env),
        &n,
        &Address::generate(&s.env),
        &2_500,
    );

    assert!(s.vault.is_nullifier_used(&BATCH_ID, &n));
    assert!(!s.vault.is_nullifier_used(&(BATCH_ID + 1), &n));
}

// ---------------------------------------------------------------------------
// Invalid withdrawals leave no trace
// ---------------------------------------------------------------------------

#[test]
fn invalid_proof_is_rejected_without_state_change() {
    let s = setup();
    s.verifier.set_result(&false);
    let recipient = Address::generate(&s.env);
    let n = nullifier(&s.env, 1);

    let result = s
        .vault
        .try_withdraw(&BATCH_ID, &proof(&s.env), &n, &recipient, &2_500);

    assert_eq!(result, Err(Ok(VaultError::InvalidProof)));
    assert!(!s.vault.is_nullifier_used(&BATCH_ID, &n));
    assert_eq!(s.vault.get_batch(&BATCH_ID).unwrap().withdrawn, 0);
    assert_eq!(s.token.balance(&recipient), 0);
}

#[test]
fn over_withdrawal_is_rejected() {
    let s = setup();
    let result = s.vault.try_withdraw(
        &BATCH_ID,
        &proof(&s.env),
        &nullifier(&s.env, 1),
        &Address::generate(&s.env),
        &(BATCH_TOTAL + 1),
    );
    assert_eq!(result, Err(Ok(VaultError::InsufficientBatchFunds)));
}

#[test]
fn withdrawal_beyond_remaining_balance_is_rejected() {
    let s = setup();
    s.vault.withdraw(
        &BATCH_ID,
        &proof(&s.env),
        &nullifier(&s.env, 1),
        &Address::generate(&s.env),
        &8_000,
    );
    let result = s.vault.try_withdraw(
        &BATCH_ID,
        &proof(&s.env),
        &nullifier(&s.env, 2),
        &Address::generate(&s.env),
        &2_001,
    );
    assert_eq!(result, Err(Ok(VaultError::InsufficientBatchFunds)));
}

#[test]
fn unknown_batch_is_rejected() {
    let s = setup();
    let result = s.vault.try_withdraw(
        &99,
        &proof(&s.env),
        &nullifier(&s.env, 1),
        &Address::generate(&s.env),
        &2_500,
    );
    assert_eq!(result, Err(Ok(VaultError::BatchNotFound)));
}

#[test]
fn invalid_amounts_are_rejected() {
    let s = setup();
    for amount in [0i128, -1, MAX_AMOUNT_EXCLUSIVE] {
        let result = s.vault.try_withdraw(
            &BATCH_ID,
            &proof(&s.env),
            &nullifier(&s.env, 1),
            &Address::generate(&s.env),
            &amount,
        );
        assert_eq!(result, Err(Ok(VaultError::InvalidAmount)));
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

#[test]
fn recipient_encoding_is_deterministic_and_fits_the_field() {
    let env = Env::default();
    let a = Address::generate(&env);
    let b = Address::generate(&env);

    let fa = recipient_to_field(&env, &a);
    assert_eq!(fa, recipient_to_field(&env, &a));
    assert_ne!(fa, recipient_to_field(&env, &b));
    assert!(fa.to_array()[0] <= 0x1f);
    assert!(is_canonical_field(&fa));
}

#[test]
fn recipient_encoding_matches_shared_vectors() {
    // Same vectors as circuits/test/recipient.test.js: proves contract and SDK agree
    extern crate std;
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../circuits/test-vectors/recipient.json"
    ))
    .unwrap();

    let env = Env::default();
    for v in vectors["vectors"].as_array().unwrap() {
        let address = v["address"].as_str().unwrap();
        let field = recipient_to_field(&env, &Address::from_str(&env, address)).to_array();
        let hex: std::string::String = field.iter().map(|b| std::format!("{b:02x}")).collect();
        assert_eq!(
            std::format!("0x{hex}"),
            v["field"].as_str().unwrap(),
            "{address}"
        );
    }
}
