// Measures proof generation for a compiled conservation circuit, using a full batch of
// random allocations.
//
// Usage: node scripts/benchmark-conservation.js <circuit-name> <depth>
//   e.g. node scripts/benchmark-conservation.js test_conservation 3
//
// Run scripts/groth16-setup.sh for the circuit first. For the depth-10 circuit, give Node more
// memory: NODE_OPTIONS=--max-old-space-size=8192.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { buildConservationInput, generateSecret, verifyConservation } = require("../lib/conservation");

function megabytes(bytes) {
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

async function timed(results, label, fn) {
    const start = process.hrtime.bigint();
    const value = await fn();
    const seconds = Number(process.hrtime.bigint() - start) / 1e9;
    results.push([label, `${seconds.toFixed(2)} s`]);
    return value;
}

async function main() {
    const [name, depthArg] = process.argv.slice(2);
    if (!name || !depthArg) {
        console.error("Usage: node scripts/benchmark-conservation.js <circuit-name> <depth>");
        process.exit(1);
    }
    const depth = Number(depthArg);
    const build = path.join(__dirname, "../build");
    const wasmPath = path.join(build, `${name}_js/${name}.wasm`);
    const zkeyPath = path.join(build, `${name}_final.zkey`);
    const vkeyPath = path.join(build, `${name}_vkey.json`);

    const allocations = Array.from({ length: 2 ** depth }, () => ({
        amount: BigInt(crypto.randomInt(1, 1_000_000_000)),
        secret: generateSecret(),
    }));
    const batchId = crypto.randomBytes(8).readBigUInt64BE();
    const results = [];

    const { input } = await timed(results, "Build input (commitments + tree)", () =>
        buildConservationInput({ allocations, batchId, depth })
    );
    const wtns = { type: "mem" };
    await timed(results, "Witness generation", () => snarkjs.wtns.calculate(input, wasmPath, wtns));
    const { proof, publicSignals } = await timed(results, "Proof generation", () =>
        snarkjs.groth16.prove(zkeyPath, wtns)
    );
    const vKey = JSON.parse(fs.readFileSync(vkeyPath, "utf8"));
    const valid = await timed(results, "Verification", () => verifyConservation(vKey, publicSignals, proof));
    if (!valid) {
        throw new Error("The proof did not verify");
    }

    results.push(["Peak memory (this process)", megabytes(process.resourceUsage().maxRSS * 1024)]);
    results.push(["Proving key (zkey)", megabytes(fs.statSync(zkeyPath).size)]);
    results.push(["Witness generator (wasm)", megabytes(fs.statSync(wasmPath).size)]);
    results.push(["Verification key", `${fs.statSync(vkeyPath).size} bytes`]);
    results.push(["Proof (JSON)", `${JSON.stringify(proof).length} bytes`]);

    console.log(`\n${name}: depth ${depth}, ${2 ** depth} allocations`);
    for (const [label, value] of results) {
        console.log(`  ${label.padEnd(36)} ${value}`);
    }
    process.exit(0);
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
