const { expect } = require("chai");
const path = require("path");
const fs = require("fs");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const { NULLIFIER_DOMAIN, computeNullifier, indexToPathIndices } = require("../lib/nullifier");

/*
 * Tests for nullifier derivation (nullifier.circom) and its binding to the commitment
 * secret, using the test_nullifier.circom harness. Witness generation only; no
 * trusted setup is needed.
 */
describe("Nullifier Derivation & Binding Circuit Tests", function () {
    this.timeout(60000);

    const LEVELS = 4; // Must match the depth in test_nullifier.circom
    const BATCH_ID = 42n;
    const wasmPath = path.join(__dirname, "../build/test_nullifier_js/test_nullifier.wasm");
    let poseidon;

    const commit = (secret, amount, batchId = BATCH_ID) =>
        BigInt(poseidon.F.toString(poseidon([amount, secret, batchId])));

    const buildInput = ({ secret, amount, leafIndex, batchId = BATCH_ID, commitment, nullifierHash, pathIndices }) => ({
        commitment: (commitment ?? commit(secret, amount, batchId)).toString(),
        nullifierHash: (nullifierHash ?? computeNullifier(poseidon, secret, leafIndex)).toString(),
        secret: secret.toString(),
        amount: amount.toString(),
        batchId: batchId.toString(),
        pathIndices: pathIndices ?? indexToPathIndices(leafIndex, LEVELS),
    });

    // Asserts that the circuit accepts the input (all constraints satisfied)
    const expectWitness = async (input, name) => {
        const witnessFile = path.join(__dirname, `../build/witness_${name}.wtns`);
        try {
            await snarkjs.wtns.calculate(input, wasmPath, witnessFile);
            expect(fs.existsSync(witnessFile)).to.be.true;
        } finally {
            if (fs.existsSync(witnessFile)) fs.unlinkSync(witnessFile);
        }
    };

    // Asserts that the circuit rejects the input (a constraint fails)
    const expectReject = async (input, name) => {
        const witnessFile = path.join(__dirname, `../build/witness_${name}.wtns`);
        try {
            await snarkjs.wtns.calculate(input, wasmPath, witnessFile);
            expect.fail(`Expected witness generation to fail: ${name}`);
        } catch (err) {
            expect(err.message).to.include("Assert Failed");
        } finally {
            if (fs.existsSync(witnessFile)) fs.unlinkSync(witnessFile);
        }
    };

    before(async () => {
        poseidon = await buildPoseidon();
    });

    it("should use the same domain tag in the circuit and the JS library", () => {
        // Guards against the two copies of the tag drifting apart
        const source = fs.readFileSync(path.join(__dirname, "../nullifier.circom"), "utf8");
        const match = source.match(/return (0x[0-9a-f]+);/);
        expect(match, "NULLIFIER_DOMAIN not found in nullifier.circom").to.not.be.null;
        expect(BigInt(match[1])).to.equal(NULLIFIER_DOMAIN);
    });

    it("should accept a correctly derived nullifier for every leaf index", async () => {
        const secret = BigInt(111111111);
        const amount = BigInt(5000);
        for (let leafIndex = 0; leafIndex < 2 ** LEVELS; leafIndex++) {
            await expectWitness(buildInput({ secret, amount, leafIndex }), `valid_${leafIndex}`);
        }
    });

    it("should give distinct nullifiers for the same secret at different leaves", () => {
        // The old Poseidon(secret) scheme fails this: one nullifier for all leaves
        const secret = BigInt(222222222);
        const nullifiers = new Set();
        for (let leafIndex = 0; leafIndex < 2 ** LEVELS; leafIndex++) {
            nullifiers.add(computeNullifier(poseidon, secret, leafIndex));
        }
        expect(nullifiers.size).to.equal(2 ** LEVELS);
    });

    it("should never equal the commitment when amount == leafIndex", () => {
        // Domain separation: without the tag these would collide and leak the leaf
        const secret = BigInt(333333333);
        for (let i = 0; i < 2 ** LEVELS; i++) {
            expect(computeNullifier(poseidon, secret, i)).to.not.equal(commit(secret, BigInt(i)));
        }
    });

    it("should reject a nullifier that does not match the secret", async () => {
        const input = buildInput({
            secret: BigInt(111111111),
            amount: BigInt(5000),
            leafIndex: 3,
            nullifierHash: BigInt(12345678), // Forged nullifier
        });
        await expectReject(input, "forged_nullifier");
    });

    it("should reject a nullifier derived for a different leaf index", async () => {
        const secret = BigInt(111111111);
        const input = buildInput({
            secret,
            amount: BigInt(5000),
            leafIndex: 3,
            nullifierHash: computeNullifier(poseidon, secret, 4), // Wrong index
        });
        await expectReject(input, "wrong_index");
    });

    it("should reject pairing allocation A's nullifier with allocation B's commitment", async () => {
        const a = { secret: BigInt(111111111), amount: BigInt(5000), leafIndex: 1 };
        const b = { secret: BigInt(444444444), amount: BigInt(20000), leafIndex: 2 };

        // Witness opens B's commitment but claims A's nullifier
        const input = buildInput({
            ...b,
            nullifierHash: computeNullifier(poseidon, a.secret, a.leafIndex),
        });
        await expectReject(input, "swapped_nullifier");
    });

    it("should reject using a different secret for the nullifier than the commitment", async () => {
        const realSecret = BigInt(111111111);
        const otherSecret = BigInt(999999999);
        const input = buildInput({
            secret: otherSecret, // Nullifier side computed from otherSecret
            amount: BigInt(5000),
            leafIndex: 3,
            commitment: commit(realSecret, BigInt(5000)), // Commitment uses realSecret
        });
        await expectReject(input, "split_secret");
    });

    it("should reject a commitment opened with a different batch identifier", async () => {
        const secret = BigInt(111111111);
        const amount = BigInt(5000);
        const input = buildInput({
            secret,
            amount,
            leafIndex: 3,
            batchId: BATCH_ID + 1n,
            commitment: commit(secret, amount, BATCH_ID),
        });
        await expectReject(input, "wrong_batch");
    });

    it("should reject non-binary path indices", async () => {
        const input = buildInput({
            secret: BigInt(111111111),
            amount: BigInt(5000),
            leafIndex: 1,
            pathIndices: [2, 0, 0, 0], // Not a bit
        });
        await expectReject(input, "non_binary_index");
    });
});
