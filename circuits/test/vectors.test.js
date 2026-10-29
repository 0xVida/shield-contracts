const { expect } = require("chai");
const path = require("path");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const { allocationCommitment, buildConservationInput } = require("../lib/conservation");
const { MerkleTree } = require("../lib/merkleTree");
const { NULLIFIER_DOMAIN, computeNullifier } = require("../lib/nullifier");
const { addressToField } = require("../lib/recipient");
const commitmentVectors = require("../test-vectors/commitment.json");
const batchVectors = require("../test-vectors/batch.json");
const nullifierVectors = require("../test-vectors/nullifier.json");
const recipientVectors = require("../test-vectors/recipient.json");

/*
 * Shared commitment, batch and nullifier vectors. The SDK, the backend and the other circuits
 * should pass the same files. A failure here means the shared protocol changed: regenerate the
 * vectors with scripts/generate-test-vectors.js only if that change is intended, and tell their
 * consumers. test/conservation.test.js runs the depth-3 batch through the conservation circuit,
 * and the last block below claims every allocation of the depth-10 batch with claim.circom.
 */
describe("Commitment & Batch Test Vectors", function () {
    this.timeout(60000);

    let poseidon;

    before(async () => {
        poseidon = await buildPoseidon();
    });

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

        it(`should match the claims in the batch vector: ${v.name}`, () => {
            const tree = new MerkleTree(v.depth, poseidon);
            v.leaves.forEach((leaf) => tree.insert(BigInt(leaf)));
            expect(v.claims.length).to.equal(v.allocations.length);

            for (const [i, claim] of v.claims.entries()) {
                const { root, pathElements, pathIndices } = tree.getProof(i);
                expect(claim.leafIndex).to.equal(i);
                expect(root).to.equal(BigInt(v.root));
                expect(claim.pathElements.map(BigInt)).to.deep.equal(pathElements);
                expect(claim.pathIndices).to.deep.equal(pathIndices);
                expect(BigInt(claim.nullifier)).to.equal(computeNullifier(poseidon, v.allocations[i].secret, i));
            }
        });
    }

    it("should use the nullifier domain tag from lib/nullifier.js", () => {
        expect(BigInt(nullifierVectors.domain)).to.equal(NULLIFIER_DOMAIN);
    });

    for (const v of nullifierVectors.vectors) {
        it(`should match the nullifier vector: ${v.name}`, () => {
            const nullifier = computeNullifier(poseidon, v.secret, v.leafIndex);
            expect(nullifier).to.equal(BigInt(v.nullifier));
            expect(nullifier.toString()).to.equal(v.nullifierDecimal);
        });
    }
});

describe("Claims Against the Shared Batch Vector", function () {
    this.timeout(60000);

    // claim.circom is the production withdraw circuit, so it takes the depth-10 batch. A batch
    // that passes the conservation circuit is only useful if every allocation in it can be claimed.
    const vector = batchVectors.batches.find((b) => b.depth === 10);
    const wasmPath = path.join(__dirname, "../build/claim_js/claim.wasm");
    const recipient = addressToField(recipientVectors.vectors[0].address);

    for (const [i, claim] of vector.claims.entries()) {
        it(`should let claim.circom claim allocation ${i} with the vector's path and nullifier`, async () => {
            const { amount, secret } = vector.allocations[i];
            const input = {
                root: BigInt(vector.root).toString(),
                nullifierHash: BigInt(claim.nullifier).toString(),
                recipient: recipient.toString(),
                amount,
                secret,
                batchId: vector.batchId,
                pathElements: claim.pathElements.map((e) => BigInt(e).toString()),
                pathIndices: claim.pathIndices,
            };
            await snarkjs.wtns.calculate(input, wasmPath, { type: "mem" });
        });
    }
});
