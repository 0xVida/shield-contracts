#![cfg(test)]
//! Tests for ShieldVault batch registration, withdrawals, nullifier tracking and
//! replay protection. Proof verification is mocked, except where a batch is
//! registered with a real conservation proof through the real ShieldVerifier.

use super::*;
use shield_verifier::{ShieldVerifier, VerifyingKey};
use soroban_sdk::{
    contract, contractimpl, symbol_short,
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation, Events as _},
    token::{StellarAssetClient, TokenClient},
    vec, Address, Bytes, BytesN, Env, Event, IntoVal, Symbol, Vec,
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
    conservation_verifier: MockVerifierClient<'a>,
    token: TokenClient<'a>,
    funder: Address,
    root: BytesN<32>,
}

/// Deploys a vault and registers a batch of BATCH_TOTAL tokens through `fund_batch`.
fn setup<'a>() -> Setup<'a> {
    let s = deploy();
    s.vault.fund_batch(
        &s.funder,
        &BATCH_ID,
        &s.token.address,
        &s.root,
        &BATCH_TOTAL,
        &proof(&s.env),
    );
    s
}

/// Deploys a vault with mock withdraw and conservation verifiers, and a funder
/// holding BATCH_TOTAL tokens. No batch is registered yet.
fn deploy<'a>() -> Setup<'a> {
    let env = Env::default();
    env.mock_all_auths();

    let verifier_id = env.register(MockVerifier, ());
    let conservation_verifier_id = env.register(MockVerifier, ());
    let vault_id = env.register(ShieldVault, (&verifier_id, &conservation_verifier_id));

    let admin = Address::generate(&env);
    let token_id = env.register_stellar_asset_contract_v2(admin).address();
    let funder = Address::generate(&env);
    StellarAssetClient::new(&env, &token_id).mint(&funder, &BATCH_TOTAL);

    Setup {
        vault: ShieldVaultClient::new(&env, &vault_id),
        verifier: MockVerifierClient::new(&env, &verifier_id),
        conservation_verifier: MockVerifierClient::new(&env, &conservation_verifier_id),
        token: TokenClient::new(&env, &token_id),
        funder,
        root: BytesN::from_array(&env, &[7u8; 32]),
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
// Batch registration
// ---------------------------------------------------------------------------

#[test]
fn fund_batch_stores_batch_and_pulls_total() {
    let s = setup();

    assert_eq!(
        s.vault.get_batch(&BATCH_ID),
        Some(Batch {
            root: s.root.clone(),
            token: s.token.address.clone(),
            total: BATCH_TOTAL,
            withdrawn: 0,
        })
    );
    assert_eq!(s.token.balance(&s.funder), 0);
    assert_eq!(s.token.balance(&s.vault.address), BATCH_TOTAL);
}

#[test]
fn fund_batch_passes_public_inputs_in_circuit_order() {
    let s = setup();

    // [root, total, batchId]
    let mut total = [0u8; 32];
    total[30..].copy_from_slice(&10_000u16.to_be_bytes());
    let mut batch_id = [0u8; 32];
    batch_id[31] = BATCH_ID as u8;
    let expected = vec![
        &s.env,
        s.root.clone(),
        BytesN::from_array(&s.env, &total),
        BytesN::from_array(&s.env, &batch_id),
    ];
    assert_eq!(s.conservation_verifier.last_inputs(), expected);
}

#[test]
fn fund_batch_emits_event() {
    let s = setup();

    let event = BatchFunded {
        batch_id: BATCH_ID,
        funder: s.funder.clone(),
        token: s.token.address.clone(),
        root: s.root.clone(),
        total: BATCH_TOTAL,
    };
    assert_eq!(
        s.env.events().all().filter_by_contract(&s.vault.address),
        [Event::to_xdr(&event, &s.env, &s.vault.address)]
    );
}

#[test]
fn fund_batch_is_authorised_by_the_funder() {
    extern crate std;
    let s = setup();

    // The funder's signature on fund_batch also covers the token transfer it makes
    let transfer = AuthorizedInvocation {
        function: AuthorizedFunction::Contract((
            s.token.address.clone(),
            symbol_short!("transfer"),
            (s.funder.clone(), s.vault.address.clone(), BATCH_TOTAL).into_val(&s.env),
        )),
        sub_invocations: std::vec![],
    };
    let fund_batch = AuthorizedInvocation {
        function: AuthorizedFunction::Contract((
            s.vault.address.clone(),
            Symbol::new(&s.env, "fund_batch"),
            (
                s.funder.clone(),
                BATCH_ID,
                s.token.address.clone(),
                s.root.clone(),
                BATCH_TOTAL,
                proof(&s.env),
            )
                .into_val(&s.env),
        )),
        sub_invocations: std::vec![transfer],
    };
    assert_eq!(s.env.auths(), std::vec![(s.funder.clone(), fund_batch)]);
}

#[test]
fn batches_cannot_draw_on_each_others_funds() {
    // Both batches hold the same token in the vault, but each pays out only its own total
    let s = setup();
    let other_funder = Address::generate(&s.env);
    StellarAssetClient::new(&s.env, &s.token.address).mint(&other_funder, &5_000);
    s.vault.fund_batch(
        &other_funder,
        &(BATCH_ID + 1),
        &s.token.address,
        &BytesN::from_array(&s.env, &[8u8; 32]),
        &5_000,
        &proof(&s.env),
    );
    assert_eq!(s.token.balance(&s.vault.address), BATCH_TOTAL + 5_000);

    let result = s.vault.try_withdraw(
        &BATCH_ID,
        &proof(&s.env),
        &nullifier(&s.env, 1),
        &Address::generate(&s.env),
        &(BATCH_TOTAL + 1),
    );
    assert_eq!(result, Err(Ok(VaultError::InsufficientBatchFunds)));
}

// ---------------------------------------------------------------------------
// Invalid registrations leave no trace
// ---------------------------------------------------------------------------

#[test]
fn invalid_conservation_proof_is_rejected_without_state_change() {
    let s = deploy();
    s.conservation_verifier.set_result(&false);

    let result = s.vault.try_fund_batch(
        &s.funder,
        &BATCH_ID,
        &s.token.address,
        &s.root,
        &BATCH_TOTAL,
        &proof(&s.env),
    );

    assert_eq!(result, Err(Ok(VaultError::InvalidProof)));
    assert_eq!(s.vault.get_batch(&BATCH_ID), None);
    assert_eq!(s.token.balance(&s.funder), BATCH_TOTAL);
}

#[test]
fn registered_batch_id_cannot_be_reused() {
    let s = setup();
    StellarAssetClient::new(&s.env, &s.token.address).mint(&s.funder, &BATCH_TOTAL);

    let result = s.vault.try_fund_batch(
        &s.funder,
        &BATCH_ID,
        &s.token.address,
        &BytesN::from_array(&s.env, &[8u8; 32]),
        &BATCH_TOTAL,
        &proof(&s.env),
    );

    assert_eq!(result, Err(Ok(VaultError::BatchExists)));
    assert_eq!(s.vault.get_batch(&BATCH_ID).unwrap().root, s.root);
    assert_eq!(s.token.balance(&s.funder), BATCH_TOTAL);
}

#[test]
fn invalid_totals_are_rejected() {
    let s = deploy();
    for total in [0i128, -1] {
        let result = s.vault.try_fund_batch(
            &s.funder,
            &BATCH_ID,
            &s.token.address,
            &s.root,
            &total,
            &proof(&s.env),
        );
        assert_eq!(result, Err(Ok(VaultError::InvalidTotal)));
    }
}

#[test]
fn non_canonical_root_is_rejected() {
    let s = deploy();
    let at_modulus = BytesN::from_array(&s.env, &FIELD_MODULUS);
    let above = BytesN::from_array(&s.env, &[0xff; 32]);

    for root in [at_modulus, above] {
        let result = s.vault.try_fund_batch(
            &s.funder,
            &BATCH_ID,
            &s.token.address,
            &root,
            &BATCH_TOTAL,
            &proof(&s.env),
        );
        assert_eq!(result, Err(Ok(VaultError::NonCanonicalRoot)));
    }
}

#[test]
fn funder_without_the_total_cannot_register() {
    let s = deploy();

    let result = s.vault.try_fund_batch(
        &s.funder,
        &BATCH_ID,
        &s.token.address,
        &s.root,
        &(BATCH_TOTAL + 1),
        &proof(&s.env),
    );

    assert!(result.is_err());
    assert_eq!(s.vault.get_batch(&BATCH_ID), None);
    assert_eq!(s.token.balance(&s.funder), BATCH_TOTAL);
}

// ---------------------------------------------------------------------------
// Batch registration with a real conservation proof
// ---------------------------------------------------------------------------

/// A real Groth16 proof for the depth-3 batch in circuits/test-vectors/batch.json, and
/// the verifying key it was made with (circuits/scripts/export-conservation-fixture.js).
struct RealBatch {
    batch_id: u64,
    root: BytesN<32>,
    total: i128,
    proof: Bytes,
    verifying_key: VerifyingKey,
}

struct RealSetup<'a> {
    env: Env,
    vault: ShieldVaultClient<'a>,
    token: TokenClient<'a>,
    funder: Address,
    batch: RealBatch,
}

/// Deploys a vault whose conservation verifier is the real ShieldVerifier, holding the
/// fixture's verifying key, and a funder holding the batch total. Withdrawals stay mocked.
fn deploy_with_real_conservation_verifier<'a>() -> RealSetup<'a> {
    let env = Env::default();
    env.mock_all_auths();
    let batch = real_batch(&env);

    let verifier_id = env.register(MockVerifier, ());
    let conservation_verifier_id = env.register(ShieldVerifier, (batch.verifying_key.clone(),));
    let vault_id = env.register(ShieldVault, (&verifier_id, &conservation_verifier_id));

    let token_id = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    let funder = Address::generate(&env);
    StellarAssetClient::new(&env, &token_id).mint(&funder, &batch.total);

    RealSetup {
        vault: ShieldVaultClient::new(&env, &vault_id),
        token: TokenClient::new(&env, &token_id),
        funder,
        batch,
        env,
    }
}

fn real_batch(env: &Env) -> RealBatch {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../circuits/test-vectors/conservation-proof.json"
    ))
    .unwrap();
    let vk = &fixture["verifyingKey"];
    let mut ic = Vec::new(env);
    for point in vk["ic"].as_array().unwrap() {
        ic.push_back(BytesN::from_array(env, &hex_array(point)));
    }
    RealBatch {
        batch_id: fixture["batchId"].as_str().unwrap().parse().unwrap(),
        root: BytesN::from_array(env, &hex_array(&fixture["root"])),
        total: fixture["total"].as_str().unwrap().parse().unwrap(),
        proof: Bytes::from_array(env, &hex_array::<256>(&fixture["proof"])),
        verifying_key: VerifyingKey {
            alpha: BytesN::from_array(env, &hex_array(&vk["alpha"])),
            beta: BytesN::from_array(env, &hex_array(&vk["beta"])),
            gamma: BytesN::from_array(env, &hex_array(&vk["gamma"])),
            delta: BytesN::from_array(env, &hex_array(&vk["delta"])),
            ic,
        },
    }
}

/// Decodes a "0x..." hex string from a JSON fixture into exactly N bytes.
fn hex_array<const N: usize>(value: &serde_json::Value) -> [u8; N] {
    let hex = value.as_str().unwrap().strip_prefix("0x").unwrap();
    assert_eq!(hex.len(), 2 * N);
    let mut bytes = [0u8; N];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    bytes
}

#[test]
fn real_conservation_proof_registers_the_batch() {
    let s = deploy_with_real_conservation_verifier();
    let b = &s.batch;

    s.vault.fund_batch(
        &s.funder,
        &b.batch_id,
        &s.token.address,
        &b.root,
        &b.total,
        &b.proof,
    );

    assert_eq!(
        s.vault.get_batch(&b.batch_id),
        Some(Batch {
            root: b.root.clone(),
            token: s.token.address.clone(),
            total: b.total,
            withdrawn: 0,
        })
    );
    assert_eq!(s.token.balance(&s.vault.address), b.total);
}

#[test]
fn real_conservation_proof_only_verifies_for_its_own_batch() {
    // The proof covers [root, total, batchId]; it is worthless for any other values
    let s = deploy_with_real_conservation_verifier();
    let b = &s.batch;
    StellarAssetClient::new(&s.env, &s.token.address).mint(&s.funder, &1);
    let mut other_root = b.root.to_array();
    other_root[31] ^= 1;

    for (batch_id, root, total) in [
        (b.batch_id, b.root.clone(), b.total + 1),
        (b.batch_id, b.root.clone(), b.total - 1),
        (b.batch_id + 1, b.root.clone(), b.total),
        (b.batch_id, BytesN::from_array(&s.env, &other_root), b.total),
    ] {
        let result = s.vault.try_fund_batch(
            &s.funder,
            &batch_id,
            &s.token.address,
            &root,
            &total,
            &b.proof,
        );
        assert_eq!(result, Err(Ok(VaultError::InvalidProof)));
        assert_eq!(s.vault.get_batch(&batch_id), None);
    }
    assert_eq!(s.token.balance(&s.vault.address), 0);
}

#[test]
fn manipulated_real_proof_is_rejected() {
    let s = deploy_with_real_conservation_verifier();
    let b = &s.batch;
    let fund = |proof: &Bytes| {
        s.vault.try_fund_batch(
            &s.funder,
            &b.batch_id,
            &s.token.address,
            &b.root,
            &b.total,
            proof,
        )
    };

    // Valid curve points in the wrong places: the pairing check fails
    let mut swapped = b.proof.slice(192..256);
    swapped.append(&b.proof.slice(64..192));
    swapped.append(&b.proof.slice(0..64));
    assert_eq!(fund(&swapped), Err(Ok(VaultError::InvalidProof)));

    // Wrong length: the verifier refuses it before any curve arithmetic
    let mut short = b.proof.clone();
    short.pop_back();
    assert_eq!(fund(&short), Err(Ok(VaultError::InvalidProof)));

    // A point that is not on the curve: the host's pairing functions abort the call
    let mut off_curve = b.proof.clone();
    off_curve.set(63, off_curve.get(63).unwrap() ^ 1);
    assert!(fund(&off_curve).is_err());

    assert_eq!(s.vault.get_batch(&b.batch_id), None);
    assert_eq!(s.token.balance(&s.funder), b.total);
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

// ---------------------------------------------------------------------------
// Storage TTL
// ---------------------------------------------------------------------------

#[test]
fn withdraw_extends_batch_and_instance_ttl() {
    use soroban_sdk::testutils::{
        storage::{Instance as _, Persistent as _},
        Ledger as _,
    };

    let s = setup();
    let ttls = |s: &Setup| {
        s.env.as_contract(&s.vault.address, || {
            (
                s.env
                    .storage()
                    .persistent()
                    .get_ttl(&DataKey::Batch(BATCH_ID)),
                s.env.storage().instance().get_ttl(),
            )
        })
    };

    // First claim: the instance is at the full period
    s.vault.withdraw(
        &BATCH_ID,
        &proof(&s.env),
        &nullifier(&s.env, 1),
        &Address::generate(&s.env),
        &1_000,
    );
    assert_eq!(ttls(&s).1, TTL_EXTEND_TO);

    // Much later, both entries have dropped below the threshold...
    let elapsed = TTL_EXTEND_TO - TTL_THRESHOLD + 1;
    s.env
        .ledger()
        .set_sequence_number(s.env.ledger().sequence() + elapsed);
    assert!(ttls(&s).0 < TTL_THRESHOLD);

    // ...and the next claim extends them back to the full period
    s.vault.withdraw(
        &BATCH_ID,
        &proof(&s.env),
        &nullifier(&s.env, 2),
        &Address::generate(&s.env),
        &1_000,
    );
    assert_eq!(ttls(&s), (TTL_EXTEND_TO, TTL_EXTEND_TO));
}

#[test]
fn fund_batch_extends_instance_ttl() {
    use soroban_sdk::testutils::storage::Instance as _;

    // setup() funds the batch; the instance starts at the network minimum
    let s = setup();
    let ttl = s
        .env
        .as_contract(&s.vault.address, || s.env.storage().instance().get_ttl());
    assert_eq!(ttl, TTL_EXTEND_TO);
}
