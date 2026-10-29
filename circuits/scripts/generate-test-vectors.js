// Writes the shared test vectors for allocation commitments, batch roots, claims and nullifiers
// (architecture.md: test vectors are produced by Person 1 and used by everyone).
//
// Usage: node scripts/generate-test-vectors.js
//
// Outputs test-vectors/commitment.json, test-vectors/batch.json and test-vectors/nullifier.json.
// Every value comes from lib/, which the circuit tests check against the circuits themselves.
// Rerun only when the shared protocol spec changes, and tell everyone who consumes the files.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { buildPoseidon } = require("circomlibjs");
const {
    FIELD_SIZE,
    MAX_AMOUNT,
    MAX_BATCH_ID,
    allocationCommitment,
    buildConservationInput,
} = require("../lib/conservation");
const { MerkleTree } = require("../lib/merkleTree");
const { NULLIFIER_DOMAIN, computeNullifier } = require("../lib/nullifier");

const outDir = path.join(__dirname, "../test-vectors");

// A fixed 248-bit secret, shaped like generateSecret() output, so the vectors are reproducible.
const SECRET_248 = BigInt("0x" + crypto.createHash("sha256").update("shieldzk test vector").digest("hex").slice(0, 62));

// One case per edge of each input's range: amount is range-checked to 64 bits in the circuit,
// batchId is the vault's u64, and secret can be any field element.
const COMMITMENT_CASES = [
    { name: "small values", amount: 50n, secret: 111111111n, batchId: 42n },
    { name: "zero amount", amount: 0n, secret: 111111111n, batchId: 42n },
    { name: "largest amount (2^64 - 1)", amount: MAX_AMOUNT, secret: 111111111n, batchId: 42n },
    { name: "largest batch id (2^64 - 1)", amount: 50n, secret: 111111111n, batchId: MAX_BATCH_ID },
    { name: "largest secret (p - 1)", amount: 50n, secret: FIELD_SIZE - 1n, batchId: 42n },
    { name: "248-bit secret, like generateSecret()", amount: 2500n, secret: SECRET_248, batchId: 7n },
];

// Alice 50, Bob 30, Carol 20, as in test/conservation.test.js.
const ALLOCATIONS = [
    { amount: 50n, secret: 111111111n },
    { amount: 30n, secret: 222222222n },
    { amount: 20n, secret: 333333333n },
];

const BATCH_CASES = [
    { name: "three allocations, depth 3 (test_conservation.circom)", depth: 3, batchId: 42n, allocations: ALLOCATIONS },
    { name: "three allocations, depth 10 (production)", depth: 10, batchId: 42n, allocations: ALLOCATIONS },
];

// The leaf index runs from 0 to 2^depth - 1 and the secret can be any field element.
const NULLIFIER_CASES = [
    { name: "first leaf", secret: 111111111n, leafIndex: 0 },
    { name: "second leaf, same secret", secret: 111111111n, leafIndex: 1 },
    { name: "last leaf at depth 10 (1023)", secret: 111111111n, leafIndex: 1023 },
    { name: "largest secret (p - 1)", secret: FIELD_SIZE - 1n, leafIndex: 5 },
    { name: "248-bit secret, like generateSecret()", secret: SECRET_248, leafIndex: 7 },
];

/** A field element as 32-byte big-endian hex, the vault's BytesN<32> encoding. */
function hex(value) {
    return "0x" + value.toString(16).padStart(64, "0");
}

function writeJson(name, data) {
    fs.writeFileSync(path.join(outDir, name), JSON.stringify(data, null, 2) + "\n");
    console.log(`Wrote test-vectors/${name}`);
}

async function main() {
    const commitments = [];
    for (const { name, amount, secret, batchId } of COMMITMENT_CASES) {
        const commitment = await allocationCommitment(amount, secret, batchId);
        commitments.push({
            name,
            amount: amount.toString(),
            secret: secret.toString(),
            batchId: batchId.toString(),
            commitment: hex(commitment),
            commitmentDecimal: commitment.toString(),
        });
    }
    writeJson("commitment.json", {
        description:
            "Allocation commitment vectors: commitment = Poseidon(amount, secret, batchId), circomlib parameters over BN254. Inputs are decimal strings; the commitment is given as 32-byte big-endian hex and as decimal. Produced by circuits/scripts/generate-test-vectors.js and checked by circuits/test/vectors.test.js.",
        vectors: commitments,
    });

    const emptyRoots = {};
    for (const depth of new Set(BATCH_CASES.map((b) => b.depth))) {
        emptyRoots[depth] = hex((await MerkleTree.create(depth)).getRoot());
    }

    const poseidon = await buildPoseidon();
    const batches = [];
    for (const { name, depth, batchId, allocations } of BATCH_CASES) {
        const { root, total } = await buildConservationInput({ allocations, batchId, depth });
        const tree = new MerkleTree(depth, poseidon);
        const leaves = [];
        for (const { amount, secret } of allocations) {
            const leaf = await allocationCommitment(amount, secret, batchId);
            tree.insert(leaf);
            leaves.push(hex(leaf));
        }
        const claims = allocations.map(({ secret }, leafIndex) => {
            const { pathElements, pathIndices } = tree.getProof(leafIndex);
            return {
                leafIndex,
                pathElements: pathElements.map(hex),
                pathIndices,
                nullifier: hex(computeNullifier(poseidon, secret, leafIndex)),
            };
        });
        batches.push({
            name,
            depth,
            batchId: batchId.toString(),
            allocations: allocations.map(({ amount, secret }) => ({ amount: amount.toString(), secret: secret.toString() })),
            leaves,
            root: hex(root),
            total: total.toString(),
            publicSignals: [root.toString(), total.toString(), batchId.toString()],
            claims,
        });
    }
    writeJson("batch.json", {
        description:
            "Batch vectors: leaves are the allocations' commitments in insertion order, every other leaf is 0, and the root is the binary Poseidon tree over all 2^depth leaves. publicSignals are the conservation circuit's public inputs [root, total, batchId] as snarkjs prints them (decimal). claims[i] is what allocation i's recipient needs to claim: its leafIndex, its Merkle path (pathElements are the sibling hashes from the leaf up; pathIndices[k] is bit k of leafIndex, 0 when the path node is a left child) and its nullifier. Field elements elsewhere are 32-byte big-endian hex. emptyRoots maps each depth to the root of a tree with no allocations. Produced by circuits/scripts/generate-test-vectors.js and checked by circuits/test/vectors.test.js and circuits/test/conservation.test.js.",
        emptyRoots,
        batches,
    });

    const nullifiers = NULLIFIER_CASES.map(({ name, secret, leafIndex }) => {
        const nullifier = computeNullifier(poseidon, secret, leafIndex);
        return {
            name,
            secret: secret.toString(),
            leafIndex,
            nullifier: hex(nullifier),
            nullifierDecimal: nullifier.toString(),
        };
    });
    writeJson("nullifier.json", {
        description:
            "Nullifier vectors: nullifier = Poseidon(domain, secret, leafIndex), circomlib parameters over BN254, where domain is the ASCII string \"shieldzk.nullifier\" read as a big-endian integer. secret is a decimal string; the nullifier is given as 32-byte big-endian hex (the vault's BytesN<32>) and as decimal. Produced by circuits/scripts/generate-test-vectors.js and checked by circuits/test/vectors.test.js.",
        domain: hex(NULLIFIER_DOMAIN),
        vectors: nullifiers,
    });
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
