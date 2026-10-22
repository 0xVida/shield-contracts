// Writes the shared test vectors for allocation commitments and batch roots
// (architecture.md: test vectors are produced by Person 1 and used by everyone).
//
// Usage: node scripts/generate-test-vectors.js
//
// Outputs test-vectors/commitment.json and test-vectors/batch.json. Every value comes from
// lib/conservation.js, which test/conservation.test.js checks against the circuit itself.
// Rerun only when the shared protocol spec changes, and tell everyone who consumes the files.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
    FIELD_SIZE,
    MAX_AMOUNT,
    MAX_BATCH_ID,
    allocationCommitment,
    buildConservationInput,
} = require("../lib/conservation");
const { MerkleTree } = require("../lib/merkleTree");

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

    const batches = [];
    for (const { name, depth, batchId, allocations } of BATCH_CASES) {
        const { root, total } = await buildConservationInput({ allocations, batchId, depth });
        const leaves = [];
        for (const { amount, secret } of allocations) {
            leaves.push(hex(await allocationCommitment(amount, secret, batchId)));
        }
        batches.push({
            name,
            depth,
            batchId: batchId.toString(),
            allocations: allocations.map(({ amount, secret }) => ({ amount: amount.toString(), secret: secret.toString() })),
            leaves,
            root: hex(root),
            total: total.toString(),
            publicSignals: [root.toString(), total.toString(), batchId.toString()],
        });
    }
    writeJson("batch.json", {
        description:
            "Batch vectors: leaves are the allocations' commitments in insertion order, every other leaf is 0, and the root is the binary Poseidon tree over all 2^depth leaves. publicSignals are the conservation circuit's public inputs [root, total, batchId] as snarkjs prints them (decimal). Field elements elsewhere are 32-byte big-endian hex. emptyRoots maps each depth to the root of a tree with no allocations. Produced by circuits/scripts/generate-test-vectors.js and checked by circuits/test/vectors.test.js and circuits/test/conservation.test.js.",
        emptyRoots,
        batches,
    });
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
