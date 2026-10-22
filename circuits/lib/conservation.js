const crypto = require("crypto");
const { buildPoseidon } = require("circomlibjs");
const snarkjs = require("snarkjs");
const { MerkleTree } = require("./merkleTree");

// BN254 scalar field size. Circuit arithmetic wraps around at this number,
// like a clock that goes back to 0 after FIELD_SIZE - 1.
const FIELD_SIZE = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Shared spec (architecture.md): amounts are token base units, range-checked to 64 bits.
const MAX_AMOUNT = (1n << 64n) - 1n;

// The vault stores batches under a u64 id, and the proof's batchId must be that same id.
const MAX_BATCH_ID = (1n << 64n) - 1n;

let poseidonPromise;

function getPoseidon() {
    if (!poseidonPromise) {
        poseidonPromise = buildPoseidon();
    }
    return poseidonPromise;
}

/**
 * Commitment for one allocation: Poseidon(amount, secret, batchId).
 * Must match AllocationCommitment() in commitment.circom.
 */
async function allocationCommitment(amount, secret, batchId) {
    const poseidon = await getPoseidon();
    return BigInt(poseidon.F.toString(poseidon([BigInt(amount), BigInt(secret), BigInt(batchId)])));
}

/**
 * Returns a fresh secret for one allocation, from a cryptographically secure source.
 *
 * The secret hides the amount and proves ownership at claim time. Each recipient's Merkle path
 * includes a neighbouring commitment, so a guessable secret would let them brute-force that
 * neighbour's amount. Never derive secrets from predictable data, and never give two recipients
 * the same one. 31 random bytes (248 bits) always fit below FIELD_SIZE.
 */
function generateSecret() {
    return BigInt("0x" + crypto.randomBytes(31).toString("hex"));
}

/**
 * Builds the input for the conservation circuit after checking every allocation the way the
 * circuit will: amounts must fit in 64 bits and secrets must be field elements. The batch ID
 * must also fit in a u64, the vault's batch id type, or the batch could never be registered.
 *
 * allocations: [{ amount, secret }] in tree order; empty slots are filled in automatically.
 * depth: tree depth of the compiled circuit (10 in production, 3 in tests).
 *
 * Returns { input, root, total }: `input` goes to snarkjs, while `root` and `total` are the
 * public values the vault stores for the batch.
 */
async function buildConservationInput({ allocations, batchId, depth }) {
    const id = BigInt(batchId);
    if (id < 0n || id > MAX_BATCH_ID) {
        throw new RangeError(`batchId ${id} does not fit in a u64, the vault's batch id type`);
    }
    allocations.forEach(({ amount, secret }, i) => {
        const value = BigInt(amount);
        if (value < 0n || value > MAX_AMOUNT) {
            throw new RangeError(`Allocation ${i}: amount ${value} does not fit in 64 bits`);
        }
        checkFieldElement(`Allocation ${i}: secret`, BigInt(secret));
    });
    return buildConservationInputUnchecked({ allocations, batchId, depth });
}

/**
 * Same as buildConservationInput, but without the checks. Tests use it to play a cheating
 * disburser and confirm the circuit itself rejects invalid allocations.
 */
async function buildConservationInputUnchecked({ allocations, batchId, depth }) {
    const poseidon = await getPoseidon();
    const numSlots = 2 ** depth;
    if (allocations.length > numSlots) {
        throw new RangeError(`A depth-${depth} tree has ${numSlots} slots, got ${allocations.length} allocations`);
    }

    const batch = BigInt(batchId);
    const tree = new MerkleTree(depth, poseidon);
    const amounts = [];
    const secrets = [];
    const active = [];
    let total = 0n;

    for (let i = 0; i < numSlots; i++) {
        if (i < allocations.length) {
            const amount = BigInt(allocations[i].amount);
            const secret = BigInt(allocations[i].secret);
            tree.insert(await allocationCommitment(amount, secret, batch));
            amounts.push(amount);
            secrets.push(secret);
            active.push(1n);
            total += amount;
        } else {
            // Empty slot: leaf 0 (spec: empty leaves = 0) and no money.
            amounts.push(0n);
            secrets.push(0n);
            active.push(0n);
        }
    }

    // The circuit adds on the same clock; this only changes anything for invalid amounts.
    total %= FIELD_SIZE;
    const root = tree.getRoot();

    return {
        input: { root, total, batchId: batch, amounts, secrets, active },
        root,
        total,
    };
}

function checkFieldElement(name, value) {
    if (value < 0n || value >= FIELD_SIZE) {
        throw new RangeError(`${name} must be a field element (0 <= value < FIELD_SIZE)`);
    }
}

/**
 * Generates a Groth16 proof that the batch's allocations add up to its total.
 * Public signals come out in the order [root, total, batchId].
 */
async function proveConservation(input, wasmPath, zkeyPath) {
    return snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
}

async function verifyConservation(verificationKey, publicSignals, proof) {
    return snarkjs.groth16.verify(verificationKey, publicSignals, proof);
}

module.exports = {
    FIELD_SIZE,
    MAX_AMOUNT,
    MAX_BATCH_ID,
    allocationCommitment,
    generateSecret,
    buildConservationInput,
    buildConservationInputUnchecked,
    proveConservation,
    verifyConservation,
};
