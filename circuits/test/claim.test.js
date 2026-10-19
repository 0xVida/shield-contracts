const { expect } = require("chai");
const path = require("path");
const fs = require("fs");
const snarkjs = require("snarkjs");
const { buildPoseidon } = require("circomlibjs");
const { MerkleTree } = require("../lib/merkleTree");
const { computeNullifier } = require("../lib/nullifier");

describe("Allocation Ownership & Claim Circuit Tests", function () {
    this.timeout(60000);

    let poseidon;
    let tree;
    const wasmPath = path.join(__dirname, "../build/claim_js/claim.wasm");

    // Recipient address encoded as field element
    const recipient = BigInt("0x1234567890abcdef1234567890abcdef12345678");

    // Allocation allocations
    const allocations = [
        { secret: BigInt(111111111), amount: BigInt(5000) },
        { secret: BigInt(222222222), amount: BigInt(12500) },
        { secret: BigInt(333333333), amount: BigInt(750) },
        { secret: BigInt(444444444), amount: BigInt(20000) },
    ];

    before(async () => {
        poseidon = await buildPoseidon();
        tree = await MerkleTree.create(10); // depth 10 (1024 allocations)

        allocations.forEach((alloc, index) => {
            const commitment = BigInt(poseidon.F.toString(poseidon([alloc.secret, alloc.amount])));
            alloc.commitment = commitment;
            alloc.nullifierHash = computeNullifier(poseidon, alloc.secret, index);
            tree.insert(commitment);
        });
    });

    it("should generate valid witness for legitimate allocation claim", async () => {
        const index = 1; // Claim allocation 1
        const alloc = allocations[index];
        const proof = tree.getProof(index);

        const input = {
            root: proof.root.toString(),
            nullifierHash: alloc.nullifierHash.toString(),
            recipient: recipient.toString(),
            amount: alloc.amount.toString(),
            secret: alloc.secret.toString(),
            pathElements: proof.pathElements.map((x) => x.toString()),
            pathIndices: proof.pathIndices,
        };

        const witnessFile = path.join(__dirname, "../build/witness_claim_valid.wtns");
        await snarkjs.wtns.calculate(input, wasmPath, witnessFile);

        expect(fs.existsSync(witnessFile)).to.be.true;
        if (fs.existsSync(witnessFile)) fs.unlinkSync(witnessFile);
    });

    it("should reject claim when secret does not match commitment", async () => {
        const index = 0;
        const alloc = allocations[index];
        const proof = tree.getProof(index);

        const input = {
            root: proof.root.toString(),
            nullifierHash: alloc.nullifierHash.toString(),
            recipient: recipient.toString(),
            amount: alloc.amount.toString(),
            secret: BigInt(999999999).toString(), // Forged secret!
            pathElements: proof.pathElements.map((x) => x.toString()),
            pathIndices: proof.pathIndices,
        };

        const witnessFile = path.join(__dirname, "../build/witness_forged_secret.wtns");
        try {
            await snarkjs.wtns.calculate(input, wasmPath, witnessFile);
            expect.fail("Expected failure with forged secret");
        } catch (err) {
            expect(err.message).to.include("Assert Failed");
        } finally {
            if (fs.existsSync(witnessFile)) fs.unlinkSync(witnessFile);
        }
    });

    it("should reject claim when amount is manipulated", async () => {
        const index = 0;
        const alloc = allocations[index];
        const proof = tree.getProof(index);

        const input = {
            root: proof.root.toString(),
            nullifierHash: alloc.nullifierHash.toString(),
            recipient: recipient.toString(),
            amount: BigInt(9999999).toString(), // Inflated amount!
            secret: alloc.secret.toString(),
            pathElements: proof.pathElements.map((x) => x.toString()),
            pathIndices: proof.pathIndices,
        };

        const witnessFile = path.join(__dirname, "../build/witness_wrong_amount.wtns");
        try {
            await snarkjs.wtns.calculate(input, wasmPath, witnessFile);
            expect.fail("Expected failure with manipulated amount");
        } catch (err) {
            expect(err.message).to.include("Assert Failed");
        } finally {
            if (fs.existsSync(witnessFile)) fs.unlinkSync(witnessFile);
        }
    });

    it("should reject claim with invalid Merkle path", async () => {
        const index = 0;
        const alloc = allocations[index];
        const proof = tree.getProof(index);

        const corruptedPath = [...proof.pathElements];
        corruptedPath[0] = BigInt(123456789); // Corrupted sibling

        const input = {
            root: proof.root.toString(),
            nullifierHash: alloc.nullifierHash.toString(),
            recipient: recipient.toString(),
            amount: alloc.amount.toString(),
            secret: alloc.secret.toString(),
            pathElements: corruptedPath.map((x) => x.toString()),
            pathIndices: proof.pathIndices,
        };

        const witnessFile = path.join(__dirname, "../build/witness_corrupted_path.wtns");
        try {
            await snarkjs.wtns.calculate(input, wasmPath, witnessFile);
            expect.fail("Expected failure with invalid Merkle path");
        } catch (err) {
            expect(err.message).to.include("Assert Failed");
        } finally {
            if (fs.existsSync(witnessFile)) fs.unlinkSync(witnessFile);
        }
    });

    it("should reject claim when nullifierHash does not match secret", async () => {
        const index = 0;
        const alloc = allocations[index];
        const proof = tree.getProof(index);

        const input = {
            root: proof.root.toString(),
            nullifierHash: BigInt(12345678).toString(), // Incorrect nullifier
            recipient: recipient.toString(),
            amount: alloc.amount.toString(),
            secret: alloc.secret.toString(),
            pathElements: proof.pathElements.map((x) => x.toString()),
            pathIndices: proof.pathIndices,
        };

        const witnessFile = path.join(__dirname, "../build/witness_wrong_nullifier.wtns");
        try {
            await snarkjs.wtns.calculate(input, wasmPath, witnessFile);
            expect.fail("Expected failure with mismatched nullifier");
        } catch (err) {
            expect(err.message).to.include("Assert Failed");
        } finally {
            if (fs.existsSync(witnessFile)) fs.unlinkSync(witnessFile);
        }
    });

    it("should reject claim when nullifierHash is derived for a different leaf index", async () => {
        const index = 0;
        const alloc = allocations[index];
        const proof = tree.getProof(index);

        const input = {
            root: proof.root.toString(),
            nullifierHash: computeNullifier(poseidon, alloc.secret, index + 1).toString(), // Wrong index
            recipient: recipient.toString(),
            amount: alloc.amount.toString(),
            secret: alloc.secret.toString(),
            pathElements: proof.pathElements.map((x) => x.toString()),
            pathIndices: proof.pathIndices,
        };

        const witnessFile = path.join(__dirname, "../build/witness_wrong_index_nullifier.wtns");
        try {
            await snarkjs.wtns.calculate(input, wasmPath, witnessFile);
            expect.fail("Expected failure with mismatched leaf index nullifier");
        } catch (err) {
            expect(err.message).to.include("Assert Failed");
        } finally {
            if (fs.existsSync(witnessFile)) fs.unlinkSync(witnessFile);
        }
    });

    describe("Groth16 Proof Verification & Frontrunning Security", () => {
        const zkeyPath = path.join(__dirname, "../build/claim_final.zkey");
        const vkeyPath = path.join(__dirname, "../build/verification_key.json");

        it("should generate and verify a valid Groth16 proof", async () => {
            const index = 2;
            const alloc = allocations[index];
            const proof = tree.getProof(index);

            const input = {
                root: proof.root.toString(),
                nullifierHash: alloc.nullifierHash.toString(),
                recipient: recipient.toString(),
                amount: alloc.amount.toString(),
                secret: alloc.secret.toString(),
                pathElements: proof.pathElements.map((x) => x.toString()),
                pathIndices: proof.pathIndices,
            };

            const { proof: zkProof, publicSignals } = await snarkjs.groth16.fullProve(
                input,
                wasmPath,
                zkeyPath
            );

            expect(publicSignals.length).to.equal(4);
            const vKey = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));
            const verified = await snarkjs.groth16.verify(vKey, publicSignals, zkProof);
            expect(verified).to.be.true;
        });

        it("should prevent frontrunning (tampering with recipient address)", async () => {
            const index = 2;
            const alloc = allocations[index];
            const proof = tree.getProof(index);

            const input = {
                root: proof.root.toString(),
                nullifierHash: alloc.nullifierHash.toString(),
                recipient: recipient.toString(),
                amount: alloc.amount.toString(),
                secret: alloc.secret.toString(),
                pathElements: proof.pathElements.map((x) => x.toString()),
                pathIndices: proof.pathIndices,
            };

            // Generate genuine proof for honest recipient
            const { proof: zkProof, publicSignals } = await snarkjs.groth16.fullProve(
                input,
                wasmPath,
                zkeyPath
            );

            // Attacker intercepts the transaction and substitutes their own address as recipient
            const attackerAddress = BigInt("0x9999999999999999999999999999999999999999").toString();
            const tamperedSignals = [...publicSignals];
            // Public signal index 2 is recipient
            tamperedSignals[2] = attackerAddress;

            const vKey = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));
            const verified = await snarkjs.groth16.verify(vKey, tamperedSignals, zkProof);
            expect(verified).to.be.false;
        });

        it("should reject tampered claim amount in public inputs", async () => {
            const index = 2;
            const alloc = allocations[index];
            const proof = tree.getProof(index);

            const input = {
                root: proof.root.toString(),
                nullifierHash: alloc.nullifierHash.toString(),
                recipient: recipient.toString(),
                amount: alloc.amount.toString(),
                secret: alloc.secret.toString(),
                pathElements: proof.pathElements.map((x) => x.toString()),
                pathIndices: proof.pathIndices,
            };

            const { proof: zkProof, publicSignals } = await snarkjs.groth16.fullProve(
                input,
                wasmPath,
                zkeyPath
            );

            // Attacker tries to increase the withdrawn amount in the public inputs
            const tamperedSignals = [...publicSignals];
            tamperedSignals[3] = BigInt(99999999).toString(); // Inflated amount

            const vKey = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));
            const verified = await snarkjs.groth16.verify(vKey, tamperedSignals, zkProof);
            expect(verified).to.be.false;
        });
    });
});
