const { expect } = require("chai");
const { allocationCommitment, buildConservationInput } = require("../lib/conservation");
const { MerkleTree } = require("../lib/merkleTree");
const commitmentVectors = require("../test-vectors/commitment.json");
const batchVectors = require("../test-vectors/batch.json");

/*
 * Shared commitment and batch vectors. The SDK, the backend and the other circuits should pass
 * the same files. A failure here means the shared protocol changed: regenerate the vectors with
 * scripts/generate-test-vectors.js only if that change is intended, and tell their consumers.
 * test/conservation.test.js runs the depth-3 batch through the circuit itself.
 */
describe("Commitment & Batch Test Vectors", function () {
    this.timeout(60000);

    for (const v of commitmentVectors.vectors) {
        it(`should match the commitment vector: ${v.name}`, async () => {
            const commitment = await allocationCommitment(v.amount, v.secret, v.batchId);
            expect(commitment).to.equal(BigInt(v.commitment));
            expect(commitment.toString()).to.equal(v.commitmentDecimal);
        });
    }

    for (const [depth, root] of Object.entries(batchVectors.emptyRoots)) {
        it(`should match the empty-tree root at depth ${depth}`, async () => {
            const tree = await MerkleTree.create(Number(depth));
            expect(tree.getRoot()).to.equal(BigInt(root));
        });
    }

    for (const v of batchVectors.batches) {
        it(`should match the batch vector: ${v.name}`, async () => {
            for (const [i, { amount, secret }] of v.allocations.entries()) {
                expect(await allocationCommitment(amount, secret, v.batchId)).to.equal(BigInt(v.leaves[i]));
            }

            const { root, total } = await buildConservationInput({
                allocations: v.allocations,
                batchId: v.batchId,
                depth: v.depth,
            });
            expect(root).to.equal(BigInt(v.root));
            expect(total.toString()).to.equal(v.total);
            expect([root, total, BigInt(v.batchId)].map(String)).to.deep.equal(v.publicSignals);
        });
    }
});
