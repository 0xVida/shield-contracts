// Writes test-vectors/conservation-proof.json: a real Groth16 conservation proof for the depth-3
// batch in test-vectors/batch.json, and the verifying key it was made with, both encoded for the
// Soroban contracts by lib/soroban.js. contracts/shield-vault/src/test.rs registers that batch
// through fund_batch with the real ShieldVerifier, and test/soroban.test.js checks it with snarkjs.
//
// Usage: node scripts/export-conservation-fixture.js
//   Needs build/test_conservation_*, from `bash scripts/groth16-setup.sh test_conservation 13`
//   (part of `pnpm build`).
//
// The key comes from that development setup, not a trusted one. Every run makes a different but
// equally valid proof, so rerun only when the circuit, the batch vector or the encoding changes.
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { buildConservationInput } = require("../lib/conservation");
const { fieldToBytes, proofToBytes, verificationKeyToSoroban } = require("../lib/soroban");
const batchVectors = require("../test-vectors/batch.json");

// Must match the depth in test_conservation.circom.
const DEPTH = 3;
const NAME = "test_conservation";

const build = path.join(__dirname, "../build");
const outPath = path.join(__dirname, "../test-vectors/conservation-proof.json");

function hex(bytes) {
    return "0x" + bytes.toString("hex");
}

async function main() {
    const vector = batchVectors.batches.find((b) => b.depth === DEPTH);
    const { input, root } = await buildConservationInput({
        allocations: vector.allocations,
        batchId: vector.batchId,
        depth: DEPTH,
    });
    if (hex(fieldToBytes(root)) !== vector.root) {
        throw new Error("test-vectors/batch.json is out of date: rerun scripts/generate-test-vectors.js");
    }

    const vkey = JSON.parse(fs.readFileSync(path.join(build, `${NAME}_vkey.json`), "utf8"));
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        path.join(build, `${NAME}_js/${NAME}.wasm`),
        path.join(build, `${NAME}_final.zkey`)
    );
    if (!(await snarkjs.groth16.verify(vkey, publicSignals, proof))) {
        throw new Error("snarkjs rejected the proof it just made: is the build out of date?");
    }

    const vk = verificationKeyToSoroban(vkey);
    const fixture = {
        description:
            "A real Groth16 proof from test_conservation.circom (Conservation(3)) for the depth-3 batch in batch.json, and the verifying key it was made with. Byte strings are hex in the contracts' encoding (circuits/lib/soroban.js): proof is A || B || C (256 bytes), verifyingKey is ShieldVerifier's constructor argument, and the vault passes publicSignals [root, total, batchId] to the verifier as 32-byte big-endian field elements. Development keys from scripts/groth16-setup.sh, not a trusted setup. Produced by circuits/scripts/export-conservation-fixture.js and checked by circuits/test/soroban.test.js and contracts/shield-vault/src/test.rs.",
        batchId: vector.batchId,
        root: vector.root,
        total: vector.total,
        publicSignals,
        proof: hex(proofToBytes(proof)),
        verifyingKey: {
            alpha: hex(vk.alpha),
            beta: hex(vk.beta),
            gamma: hex(vk.gamma),
            delta: hex(vk.delta),
            ic: vk.ic.map(hex),
        },
    };
    fs.writeFileSync(outPath, JSON.stringify(fixture, null, 2) + "\n");
    console.log("Wrote test-vectors/conservation-proof.json");
    // snarkjs leaves worker threads running
    process.exit(0);
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
