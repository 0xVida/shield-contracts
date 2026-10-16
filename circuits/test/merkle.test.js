const { expect } = require("chai");
const path = require("path");
const fs = require("fs");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const { MerkleTree } = require("../lib/merkleTree");

describe("Merkle Proof Circuit Tests", function () {
    this.timeout(60000);

    let poseidon;
    let tree;
    const wasmPath = path.join(__dirname, "../build/test_merkle_js/test_merkle.wasm");

    before(async () => {
        poseidon = await buildPoseidon();
        tree = await MerkleTree.create(4); // depth 4 (16 leaves)
    });

    it("should verify valid membership for all leaves in a tree", async () => {
        const numLeaves = 8;
        const leaves = [];

        for (let i = 0; i < numLeaves; i++) {
            const leaf = BigInt(poseidon.F.toString(poseidon([BigInt(i + 100), BigInt(i * 10)])));
            leaves.push(leaf);
            tree.insert(leaf);
        }

        const expectedRoot = tree.getRoot();

        for (let i = 0; i < numLeaves; i++) {
            const proof = tree.getProof(i);
            expect(proof.root).to.equal(expectedRoot);

            const input = {
                leaf: leaves[i].toString(),
                pathElements: proof.pathElements.map((x) => x.toString()),
                pathIndices: proof.pathIndices,
            };

            const witnessFile = path.join(__dirname, `../build/witness_${i}.wtns`);
            await snarkjs.wtns.calculate(input, wasmPath, witnessFile);

            // Clean up witness file
            if (fs.existsSync(witnessFile)) {
                fs.unlinkSync(witnessFile);
            }
        }
    });

    it("should reject an invalid path element (tampered sibling)", async () => {
        const proof = tree.getProof(0);
        // Tamper with sibling
        const tamperedPath = [...proof.pathElements];
        tamperedPath[0] = BigInt(99999999);

        const input = {
            leaf: tree.leaves[0].toString(),
            pathElements: tamperedPath.map((x) => x.toString()),
            pathIndices: proof.pathIndices,
        };

        const witnessFile = path.join(__dirname, "../build/witness_tampered.wtns");
        await snarkjs.wtns.calculate(input, wasmPath, witnessFile);

        // Export witness to check computed root
        const signals = await snarkjs.wtns.exportJson(witnessFile);
        
        // Signal index 1 is output 'root'
        const computedRoot = BigInt(signals[1]);
        expect(computedRoot).to.not.equal(tree.getRoot());

        // Clean up
        if (fs.existsSync(witnessFile)) fs.unlinkSync(witnessFile);
    });

    it("should fail constraint when path index is non-binary", async () => {
        const proof = tree.getProof(0);
        const invalidIndices = [...proof.pathIndices];
        invalidIndices[0] = 2; // Non-binary value (must fail pathIndices * (1 - pathIndices) === 0)

        const input = {
            leaf: tree.leaves[0].toString(),
            pathElements: proof.pathElements.map((x) => x.toString()),
            pathIndices: invalidIndices,
        };

        const witnessFile = path.join(__dirname, "../build/witness_nonbinary.wtns");
        try {
            await snarkjs.wtns.calculate(input, wasmPath, witnessFile);
            expect.fail("Expected constraint failure for non-binary index");
        } catch (err) {
            expect(err.message).to.include("Assert Failed");
        } finally {
            if (fs.existsSync(witnessFile)) fs.unlinkSync(witnessFile);
        }
    });
});
