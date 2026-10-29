const { expect } = require("chai");
const path = require("path");
const fs = require("fs");
const snarkjs = require("snarkjs");
const {
    FIELD_SIZE,
    MAX_AMOUNT,
    MAX_BATCH_ID,
    buildConservationInput,
    buildConservationInputUnchecked,
    generateSecret,
    proveConservation,
    verifyConservation,
} = require("../lib/conservation");
const batchVectors = require("../test-vectors/batch.json");

// Must match the depth in test_conservation.circom.
const DEPTH = 3;
const BATCH_ID = 42n;

const wasmPath = path.join(__dirname, "../build/test_conservation_js/test_conservation.wasm");
const zkeyPath = path.join(__dirname, "../build/test_conservation_final.zkey");
const vkeyPath = path.join(__dirname, "../build/test_conservation_vkey.json");

// Alice 50, Bob 30, Carol 20: the batch total is 100.
const HONEST_ALLOCATIONS = [
    { amount: 50n, secret: 111111111n },
    { amount: 30n, secret: 222222222n },
    { amount: 20n, secret: 333333333n },
];

function honestBatch() {
    return buildConservationInput({ allocations: HONEST_ALLOCATIONS, batchId: BATCH_ID, depth: DEPTH });
}

async function expectAccepted(input) {
    await snarkjs.wtns.calculate(input, wasmPath, { type: "mem" });
}

async function expectRejected(input) {
    try {
        await snarkjs.wtns.calculate(input, wasmPath, { type: "mem" });
    } catch (err) {
        expect(err.message).to.include("Assert Failed");
        return;
    }
    expect.fail("Expected the circuit to reject this input");
}

async function expectRangeError(promise) {
    let error;
    try {
        await promise;
    } catch (err) {
        error = err;
    }
    expect(error).to.be.instanceOf(RangeError);
}

describe("Balance Conservation Circuit Tests", function () {
    this.timeout(60000);

    describe("Valid batches", () => {
        it("should accept an honest batch whose allocations add up to the total", async () => {
            const { input, total } = await honestBatch();
            expect(total).to.equal(100n);
            await expectAccepted(input);
        });

        it("should accept a full batch with every amount at the 64-bit maximum", async () => {
            const allocations = Array.from({ length: 2 ** DEPTH }, (_, i) => ({
                amount: MAX_AMOUNT,
                secret: BigInt(i + 1),
            }));
            const { input } = await buildConservationInput({ allocations, batchId: BATCH_ID, depth: DEPTH });
            await expectAccepted(input);
        });

        it("should accept the largest batch ID the vault can store", async () => {
            const { input } = await buildConservationInput({
                allocations: HONEST_ALLOCATIONS,
                batchId: MAX_BATCH_ID,
                depth: DEPTH,
            });
            await expectAccepted(input);
        });

        it("should accept the depth-3 batch from the shared test vectors", async () => {
            const vector = batchVectors.batches.find((b) => b.depth === DEPTH);
            const { input } = await buildConservationInput({
                allocations: vector.allocations,
                batchId: vector.batchId,
                depth: DEPTH,
            });
            // Public values straight from the vector, so the circuit itself confirms its root.
            input.root = BigInt(vector.root);
            input.total = BigInt(vector.total);
            await expectAccepted(input);
        });
    });

    describe("Incorrect totals", () => {
        it("should reject a total that is one too high", async () => {
            const { input, total } = await honestBatch();
            input.total = total + 1n;
            await expectRejected(input);
        });

        it("should reject a total that is one too low", async () => {
            const { input, total } = await honestBatch();
            input.total = total - 1n;
            await expectRejected(input);
        });
    });

    describe("Allocations left out of the total", () => {
        // An allocation that is committed under the root but not counted would let a disburser
        // hand out more than it deposited: the leaf stays claimable, but the total omits it.
        it("should reject marking a committed allocation as an empty slot", async () => {
            const { input, total } = await honestBatch();
            input.active[2] = 0n;
            input.amounts[2] = 0n;
            input.total = total - 20n;
            await expectRejected(input);
        });

        it("should reject counting a committed allocation as zero", async () => {
            const { input, total } = await honestBatch();
            input.amounts[2] = 0n;
            input.total = total - 20n;
            await expectRejected(input);
        });

        it("should reject counting a duplicated allocation only once", async () => {
            // Carol's commitment sits in two slots, and each leaf has its own nullifier,
            // so both could be claimed.
            const { input } = await buildConservationInputUnchecked({
                allocations: [...HONEST_ALLOCATIONS, HONEST_ALLOCATIONS[2]],
                batchId: BATCH_ID,
                depth: DEPTH,
            });
            expect(input.total).to.equal(120n);
            input.total = 100n;
            await expectRejected(input);
        });
    });

    describe("Invalid allocations", () => {
        it("should reject the clock trick: an amount of p - 20 that acts like -20", async () => {
            // Carol's allocation says 40 instead of 20, and an extra one holds p - 20.
            // On the circuit's clock the four amounts add up to 100, matching the deposit.
            const { input, total } = await buildConservationInputUnchecked({
                allocations: [
                    { amount: 50n, secret: 111111111n },
                    { amount: 30n, secret: 222222222n },
                    { amount: 40n, secret: 333333333n },
                    { amount: FIELD_SIZE - 20n, secret: 444444444n },
                ],
                batchId: BATCH_ID,
                depth: DEPTH,
            });
            expect(total).to.equal(100n);
            await expectRejected(input);
        });

        it("should reject an amount of exactly 2^64", async () => {
            const { input } = await buildConservationInputUnchecked({
                allocations: [{ amount: MAX_AMOUNT + 1n, secret: 111111111n }],
                batchId: BATCH_ID,
                depth: DEPTH,
            });
            await expectRejected(input);
        });

        it("should reject money placed in an empty slot", async () => {
            const { input, total } = await honestBatch();
            // Slot 7 is empty (its leaf stays 0), so these 5 tokens could never be claimed.
            input.amounts[7] = 5n;
            input.total = total + 5n;
            await expectRejected(input);
        });

        it("should reject an active flag that is not 0 or 1", async () => {
            const { input } = await honestBatch();
            input.active[0] = 2n;
            await expectRejected(input);
        });
    });

    describe("Manipulated commitments", () => {
        it("should reject amounts changed after the root was computed", async () => {
            const { input } = await honestBatch();
            // Alice 60 and Bob 20 still add up to 100, but no longer match the committed leaves.
            input.amounts[0] = 60n;
            input.amounts[1] = 20n;
            await expectRejected(input);
        });

        it("should reject a secret changed after the root was computed", async () => {
            const { input } = await honestBatch();
            input.secrets[2] = 999999999n;
            await expectRejected(input);
        });

        it("should reject commitments made for a different batch", async () => {
            const { input } = await honestBatch();
            input.batchId = BATCH_ID + 1n;
            await expectRejected(input);
        });

        it("should reject a root that does not belong to the allocations", async () => {
            const { input, root } = await honestBatch();
            input.root = root + 1n;
            await expectRejected(input);
        });
    });

    describe("Input builder", () => {
        it("should refuse amounts outside the 64-bit range", async () => {
            for (const amount of [-1n, MAX_AMOUNT + 1n]) {
                await expectRangeError(
                    buildConservationInput({
                        allocations: [{ amount, secret: 111111111n }],
                        batchId: BATCH_ID,
                        depth: DEPTH,
                    })
                );
            }
        });

        it("should refuse more allocations than the tree has slots", async () => {
            const allocations = Array.from({ length: 2 ** DEPTH + 1 }, (_, i) => ({ amount: 1n, secret: BigInt(i + 1) }));
            await expectRangeError(buildConservationInput({ allocations, batchId: BATCH_ID, depth: DEPTH }));
        });

        it("should refuse two allocations with the same secret", async () => {
            // Whoever holds the shared secret could claim both allocations
            await expectRangeError(
                buildConservationInput({
                    allocations: [...HONEST_ALLOCATIONS, { amount: 40n, secret: HONEST_ALLOCATIONS[0].secret }],
                    batchId: BATCH_ID,
                    depth: DEPTH,
                })
            );
        });

        it("should refuse a batch ID that does not fit in a u64", async () => {
            // The vault stores batches under a u64 id, so such a batch could never be registered.
            for (const batchId of [-1n, MAX_BATCH_ID + 1n]) {
                await expectRangeError(
                    buildConservationInput({ allocations: HONEST_ALLOCATIONS, batchId, depth: DEPTH })
                );
            }
        });

        it("should generate distinct secrets that are field elements", () => {
            const secrets = new Set(Array.from({ length: 100 }, () => generateSecret()));
            expect(secrets.size).to.equal(100);
            for (const secret of secrets) {
                expect(secret >= 0n && secret < FIELD_SIZE).to.be.true;
            }
        });
    });

    describe("Groth16 Proof Generation & Verification", () => {
        let vKey;
        let batch;
        let zkProof;
        let publicSignals;

        before(async () => {
            vKey = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));
            batch = await honestBatch();
            ({ proof: zkProof, publicSignals } = await proveConservation(batch.input, wasmPath, zkeyPath));
        });

        it("should generate a proof that verifies, with public signals [root, total, batchId]", async () => {
            expect(publicSignals).to.deep.equal([batch.root.toString(), "100", BATCH_ID.toString()]);
            expect(await verifyConservation(vKey, publicSignals, zkProof)).to.be.true;
        });

        it("should fail verification if the total is changed", async () => {
            const tamperedSignals = [...publicSignals];
            tamperedSignals[1] = "101";
            expect(await verifyConservation(vKey, tamperedSignals, zkProof)).to.be.false;
        });

        it("should fail verification if the root is changed", async () => {
            const tamperedSignals = [...publicSignals];
            tamperedSignals[0] = (batch.root + 1n).toString();
            expect(await verifyConservation(vKey, tamperedSignals, zkProof)).to.be.false;
        });

        it("should fail verification if the proof is reused for another batch", async () => {
            const tamperedSignals = [...publicSignals];
            tamperedSignals[2] = (BATCH_ID + 1n).toString();
            expect(await verifyConservation(vKey, tamperedSignals, zkProof)).to.be.false;
        });
    });
});
