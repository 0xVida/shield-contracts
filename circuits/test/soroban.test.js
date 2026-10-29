const { expect } = require("chai");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { FIELD_SIZE, buildConservationInput } = require("../lib/conservation");
const {
    BASE_FIELD_SIZE,
    fieldToBytes,
    g2ToBytes,
    proofToBytes,
    verificationKeyToSoroban,
} = require("../lib/soroban");
const batchVectors = require("../test-vectors/batch.json");
const fixture = require("../test-vectors/conservation-proof.json");

/*
 * Encoding of proofs and verifying keys for the Soroban contracts (lib/soroban.js). Here the
 * committed fixture is decoded and checked by snarkjs; contracts/shield-vault/src/test.rs runs
 * the same fixture through the real ShieldVerifier.
 */

// The inverse of lib/soroban.js, so snarkjs can check exactly what the contracts receive.
function words(bytes) {
    return Array.from({ length: bytes.length / 32 }, (_, i) =>
        BigInt("0x" + bytes.subarray(32 * i, 32 * (i + 1)).toString("hex")).toString()
    );
}

function g1FromBytes(bytes) {
    const [x, y] = words(bytes);
    return [x, y, "1"];
}

function g2FromBytes(bytes) {
    const [x1, x0, y1, y0] = words(bytes);
    return [[x0, x1], [y0, y1], ["1", "0"]];
}

function proofFromBytes(bytes) {
    return {
        protocol: "groth16",
        curve: "bn128",
        pi_a: g1FromBytes(bytes.subarray(0, 64)),
        pi_b: g2FromBytes(bytes.subarray(64, 192)),
        pi_c: g1FromBytes(bytes.subarray(192, 256)),
    };
}

function verificationKeyFromSoroban(vk) {
    return {
        protocol: "groth16",
        curve: "bn128",
        nPublic: vk.ic.length - 1,
        vk_alpha_1: g1FromBytes(vk.alpha),
        vk_beta_2: g2FromBytes(vk.beta),
        vk_gamma_2: g2FromBytes(vk.gamma),
        vk_delta_2: g2FromBytes(vk.delta),
        IC: vk.ic.map(g1FromBytes),
    };
}

function fromHex(value) {
    return Buffer.from(value.slice(2), "hex");
}

function fixtureKey() {
    const { alpha, beta, gamma, delta, ic } = fixture.verifyingKey;
    return verificationKeyFromSoroban({
        alpha: fromHex(alpha),
        beta: fromHex(beta),
        gamma: fromHex(gamma),
        delta: fromHex(delta),
        ic: ic.map(fromHex),
    });
}

describe("Soroban Proof Encoding", function () {
    this.timeout(60000);

    describe("Layout", () => {
        it("should encode field elements as 32 big-endian bytes", () => {
            expect(fieldToBytes(258n).toString("hex")).to.equal("00".repeat(30) + "0102");
            expect(fieldToBytes(FIELD_SIZE - 1n).toString("hex")).to.equal((FIELD_SIZE - 1n).toString(16));
        });

        it("should refuse values that are not canonical field elements", () => {
            // The verifier would read r + n as n, so only the canonical encoding is allowed
            for (const value of [-1n, FIELD_SIZE]) {
                expect(() => fieldToBytes(value)).to.throw(RangeError);
            }
        });

        it("should use the BN254 base field for point coordinates", () => {
            // p from soroban-sdk's crypto/bn254.rs; coordinates are below p, not below r
            expect(BASE_FIELD_SIZE).to.equal(0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47n);
            expect(() => g2ToBytes([[BASE_FIELD_SIZE, 0n], [0n, 0n], ["1", "0"]])).to.throw(RangeError);
        });

        it("should put each G2 coordinate's c1 half before its c0 half", () => {
            // snarkjs prints [[x.c0, x.c1], [y.c0, y.c1]]; Soroban reads x.c1 || x.c0 || y.c1 || y.c0
            expect(words(g2ToBytes([["1", "2"], ["3", "4"], ["1", "0"]]))).to.deep.equal(["2", "1", "4", "3"]);
        });

        it("should lay out a proof as A || B || C", () => {
            const bytes = proofToBytes({
                pi_a: ["5", "6", "1"],
                pi_b: [["7", "8"], ["9", "10"], ["1", "0"]],
                pi_c: ["11", "12", "1"],
            });
            expect(bytes.length).to.equal(256);
            expect(words(bytes)).to.deep.equal(["5", "6", "8", "7", "10", "9", "11", "12"]);
        });

        it("should refuse points that are not in affine form", () => {
            expect(() =>
                proofToBytes({ pi_a: ["5", "6", "2"], pi_b: [["7", "8"], ["9", "10"], ["1", "0"]], pi_c: ["11", "12", "1"] })
            ).to.throw(RangeError);
        });
    });

    describe("Committed fixture (test-vectors/conservation-proof.json)", () => {
        it("should prove the depth-3 batch vector", () => {
            const vector = batchVectors.batches.find((b) => b.depth === 3);
            expect([fixture.batchId, fixture.root, fixture.total]).to.deep.equal([vector.batchId, vector.root, vector.total]);
            expect(fixture.publicSignals).to.deep.equal(vector.publicSignals);
        });

        it("should hold a 256-byte proof and one IC point per public input, plus one", () => {
            expect(fromHex(fixture.proof).length).to.equal(256);
            expect(fixture.verifyingKey.ic.length).to.equal(fixture.publicSignals.length + 1);
        });

        it("should verify with snarkjs after decoding", async () => {
            const proof = proofFromBytes(fromHex(fixture.proof));
            expect(await snarkjs.groth16.verify(fixtureKey(), fixture.publicSignals, proof)).to.be.true;
        });

        it("should not verify for a different total", async () => {
            const proof = proofFromBytes(fromHex(fixture.proof));
            const signals = [...fixture.publicSignals];
            signals[1] = (BigInt(signals[1]) + 1n).toString();
            expect(await snarkjs.groth16.verify(fixtureKey(), signals, proof)).to.be.false;
        });
    });

    describe("Fresh proofs", () => {
        const build = path.join(__dirname, "../build");

        it("should encode a new proof and key so that they still verify, and decode back to the same bytes", async () => {
            const vector = batchVectors.batches.find((b) => b.depth === 3);
            const { input } = await buildConservationInput({
                allocations: vector.allocations,
                batchId: vector.batchId,
                depth: 3,
            });
            const { proof, publicSignals } = await snarkjs.groth16.fullProve(
                input,
                path.join(build, "test_conservation_js/test_conservation.wasm"),
                path.join(build, "test_conservation_final.zkey")
            );
            const vkey = JSON.parse(fs.readFileSync(path.join(build, "test_conservation_vkey.json"), "utf8"));

            const proofBytes = proofToBytes(proof);
            const vk = verificationKeyToSoroban(vkey);
            const decoded = proofFromBytes(proofBytes);
            expect(await snarkjs.groth16.verify(verificationKeyFromSoroban(vk), publicSignals, decoded)).to.be.true;
            expect(proofToBytes(decoded).equals(proofBytes)).to.be.true;
        });
    });
});
