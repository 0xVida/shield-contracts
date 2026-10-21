#![no_std]
//! ShieldVault custodies confidential disbursement batches and releases funds to
//! recipients who prove ownership of an allocation with a zero-knowledge proof.
//!
//! Ownership (see shield-platform/docs/team.md):
//! - Batch registration and funding: Person 1 (not in this file yet)
//! - Claim validation / proof verification: Person 2 (behind `VerifierClient`)
//! - Nullifier tracking and fund release: Person 3 (`withdraw`, this file)

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype,
    token::TokenClient, xdr::ToXdr, Address, Bytes, BytesN, Env, Vec,
};

/// BN254 scalar field modulus r, big-endian. Every public input to the Groth16
/// verifier must be a canonical field element (strictly less than r).
const FIELD_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Amounts are range-checked to 64 bits in the circuits, so the vault enforces the same bound.
const MAX_AMOUNT_EXCLUSIVE: i128 = 1 << 64;

/// Persistent-storage TTL policy (in ledgers): when an entry has fewer than
/// `TTL_THRESHOLD` ledgers left, extend it to `TTL_EXTEND_TO` (~30 days at 5s/ledger).
const TTL_THRESHOLD: u32 = 100_000;
const TTL_EXTEND_TO: u32 = 518_400;

/// A funded disbursement batch.
///
/// Layout proposed to @IbrahimIjai (Person 1), who owns creating batches. Withdraw
/// only reads `root` and `token`, and updates `withdrawn`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Batch {
    /// Merkle root of the batch's allocation commitments (BN254 field element, big-endian).
    pub root: BytesN<32>,
    /// Token the batch was funded in.
    pub token: Address,
    /// Total amount deposited for the batch.
    pub total: i128,
    /// Total amount withdrawn so far. Invariant: `withdrawn <= total`.
    pub withdrawn: i128,
}

/// Storage keys.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Address of the Groth16 verifier contract (instance storage).
    Verifier,
    /// Batch data by batch id (persistent storage).
    Batch(u64),
    /// Spent marker for a nullifier, scoped to its batch (persistent storage).
    Nullifier(u64, BytesN<32>),
}

/// Errors returned by the vault. Any error aborts the call and rolls back all state changes.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VaultError {
    /// No batch exists with the given id.
    BatchNotFound = 1,
    /// The nullifier has already been used in this batch (double claim / replay).
    NullifierUsed = 2,
    /// The verifier rejected the proof for these public inputs.
    InvalidProof = 3,
    /// Amount is zero, negative, or does not fit in 64 bits.
    InvalidAmount = 4,
    /// Paying this amount would withdraw more than the batch was funded with.
    InsufficientBatchFunds = 5,
    /// The nullifier is not a canonical field element (>= field modulus).
    NonCanonicalNullifier = 6,
}

/// Interface the vault expects from the Groth16 verifier contract.
///
/// `public_inputs` are 32-byte big-endian field elements in the circuit's public
/// signal order: [root, nullifierHash, recipient, amount].
#[contractclient(name = "VerifierClient")]
pub trait VerifierInterface {
    fn verify(env: Env, proof: Bytes, public_inputs: Vec<BytesN<32>>) -> bool;
}

/// Emitted after a successful withdrawal.
#[contractevent(topics = ["shield", "withdrawn"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Withdrawn {
    #[topic]
    pub batch_id: u64,
    pub nullifier: BytesN<32>,
    pub recipient: Address,
    pub amount: i128,
}

#[contract]
pub struct ShieldVault;

#[contractimpl]
impl ShieldVault {
    /// Deploys the vault with the address of the Groth16 verifier contract.
    pub fn __constructor(env: Env, verifier: Address) {
        env.storage().instance().set(&DataKey::Verifier, &verifier);
    }

    /// Releases an allocation to `recipient` if `proof` is valid for this batch.
    ///
    /// Anyone may submit the call (e.g. a relayer paying fees on the recipient's
    /// behalf): the proof binds `recipient` and `amount`, so a submitter cannot
    /// redirect or change the payout.
    ///
    /// Order of operations: validate inputs, verify the proof, record the nullifier
    /// and the withdrawn amount, and only then transfer tokens.
    pub fn withdraw(
        env: Env,
        batch_id: u64,
        proof: Bytes,
        nullifier: BytesN<32>,
        recipient: Address,
        amount: i128,
    ) -> Result<(), VaultError> {
        // 1. Cheap input checks
        if amount <= 0 || amount >= MAX_AMOUNT_EXCLUSIVE {
            return Err(VaultError::InvalidAmount);
        }
        // A non-canonical nullifier (n + r) could verify like n but use a different
        // storage key, allowing the same allocation to be claimed twice.
        if !is_canonical_field(&nullifier) {
            return Err(VaultError::NonCanonicalNullifier);
        }

        // 2. Batch must exist and have enough remaining funds
        let batch_key = DataKey::Batch(batch_id);
        let mut batch: Batch = env
            .storage()
            .persistent()
            .get(&batch_key)
            .ok_or(VaultError::BatchNotFound)?;
        let withdrawn = batch.withdrawn + amount;
        if withdrawn > batch.total {
            return Err(VaultError::InsufficientBatchFunds);
        }

        // 3. Nullifier must not have been used in this batch
        let nullifier_key = DataKey::Nullifier(batch_id, nullifier.clone());
        if env.storage().persistent().has(&nullifier_key) {
            return Err(VaultError::NullifierUsed);
        }

        // 4. Verify the proof against the batch's stored root (never a caller-supplied
        //    root), in the circuit's public input order
        let mut public_inputs = Vec::new(&env);
        public_inputs.push_back(batch.root.clone());
        public_inputs.push_back(nullifier.clone());
        public_inputs.push_back(recipient_to_field(&env, &recipient));
        public_inputs.push_back(amount_to_field(&env, amount));

        let verifier: Address = env.storage().instance().get(&DataKey::Verifier).unwrap();
        if !VerifierClient::new(&env, &verifier).verify(&proof, &public_inputs) {
            return Err(VaultError::InvalidProof);
        }

        // 5. Effects: mark the nullifier spent and record the withdrawal
        env.storage().persistent().set(&nullifier_key, &true);
        env.storage()
            .persistent()
            .extend_ttl(&nullifier_key, TTL_THRESHOLD, TTL_EXTEND_TO);
        batch.withdrawn = withdrawn;
        env.storage().persistent().set(&batch_key, &batch);

        // 6. Interaction: pay the recipient from the vault's balance
        TokenClient::new(&env, &batch.token).transfer(
            &env.current_contract_address(),
            &recipient,
            &amount,
        );

        Withdrawn {
            batch_id,
            nullifier,
            recipient,
            amount,
        }
        .publish(&env);

        Ok(())
    }

    /// Returns true if `nullifier` has already been used to withdraw from `batch_id`.
    pub fn is_nullifier_used(env: Env, batch_id: u64, nullifier: BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Nullifier(batch_id, nullifier))
    }

    /// Returns the batch with the given id, if it exists.
    pub fn get_batch(env: Env, batch_id: u64) -> Option<Batch> {
        env.storage().persistent().get(&DataKey::Batch(batch_id))
    }
}

/// Encodes a Stellar address as a BN254 field element for the proof's `recipient` input:
/// sha256 of the address's XDR, with the top 3 bits cleared so it fits in 253 bits (< r).
///
/// Agreed encoding (architecture D4). The SDK must compute exactly the same value
/// off-chain (circuits/lib/recipient.js), or valid proofs will be rejected; both are
/// checked against circuits/test-vectors/recipient.json.
pub fn recipient_to_field(env: &Env, recipient: &Address) -> BytesN<32> {
    let hash = env.crypto().sha256(&recipient.clone().to_xdr(env));
    let mut bytes = hash.to_array();
    bytes[0] &= 0x1f;
    BytesN::from_array(env, &bytes)
}

/// Encodes an amount (0 < amount < 2^64) as a 32-byte big-endian field element.
fn amount_to_field(env: &Env, amount: i128) -> BytesN<32> {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&amount.to_be_bytes());
    BytesN::from_array(env, &bytes)
}

/// Returns true if `value` (big-endian) is strictly less than the BN254 field modulus.
fn is_canonical_field(value: &BytesN<32>) -> bool {
    value.to_array() < FIELD_MODULUS
}

mod test;
