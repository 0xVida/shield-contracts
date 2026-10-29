/*
 * snarkjs Groth16 output -> the byte formats the Soroban contracts read.
 *
 *   field element   32 bytes, big-endian (the vault's BytesN<32>)
 *   G1 point        be(x) || be(y), 64 bytes
 *   G2 point        be(x.c1) || be(x.c0) || be(y.c1) || be(y.c0), 128 bytes
 *   proof           A || B || C, 256 bytes (ShieldVerifier.verify)
 *   verifying key   ShieldVerifier's VerifyingKey { alpha, beta, gamma, delta, ic }
 *
 * Points use Soroban's BN254 encoding, which is Ethereum's (EIP-197). snarkjs stores the
 * two halves of a G2 coordinate the other way round, as [c0, c1], so they are swapped here.
 * Must match contracts/shield-verifier/src/lib.rs; contracts/shield-vault/src/test.rs runs
 * a proof encoded by this file through the real verifier.
 */
const { FIELD_SIZE } = require("./conservation");

// The base field of BN254, in which point coordinates live. Not the same as FIELD_SIZE,
// the scalar field that circuit signals and public inputs live in.
const BASE_FIELD_SIZE = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

/**
 * Encodes a public input (or a root, nullifier, total...) as 32 big-endian bytes.
 * Throws on a non-canonical value, which the verifier and the vault reject anyway.
 *
 * @param {bigint|string|number} value A field element.
 * @returns {Buffer} 32 bytes.
 */
function fieldToBytes(value) {
    const v = BigInt(value);
    if (v < 0n || v >= FIELD_SIZE) {
        throw new RangeError(`Not a canonical field element: ${v}`);
    }
    return uint256(v);
}

/** One point coordinate as 32 big-endian bytes. */
function coordinate(value) {
    const v = BigInt(value);
    if (v < 0n || v >= BASE_FIELD_SIZE) {
        throw new RangeError(`Not a BN254 base field element: ${v}`);
    }
    return uint256(v);
}

function uint256(v) {
    return Buffer.from(v.toString(16).padStart(64, "0"), "hex");
}

/**
 * Encodes a G1 point from snarkjs ([x, y, "1"]) as 64 bytes.
 *
 * @param {Array<string>} point Affine point as snarkjs prints it.
 * @returns {Buffer} 64 bytes.
 */
function g1ToBytes(point) {
    checkAffine(point[2], "1");
    return Buffer.concat([coordinate(point[0]), coordinate(point[1])]);
}

/**
 * Encodes a G2 point from snarkjs ([[x.c0, x.c1], [y.c0, y.c1], ["1", "0"]]) as 128 bytes.
 *
 * @param {Array<Array<string>>} point Affine point as snarkjs prints it.
 * @returns {Buffer} 128 bytes.
 */
function g2ToBytes(point) {
    checkAffine(point[2][0], "1");
    checkAffine(point[2][1], "0");
    const [[x0, x1], [y0, y1]] = point;
    return Buffer.concat([coordinate(x1), coordinate(x0), coordinate(y1), coordinate(y0)]);
}

// snarkjs prints proofs and keys in affine form (z = 1). Anything else would need converting.
function checkAffine(actual, expected) {
    if (BigInt(actual) !== BigInt(expected)) {
        throw new RangeError("Expected an affine point (z = 1), as snarkjs prints proofs and keys");
    }
}

/**
 * Encodes a Groth16 proof from snarkjs as the 256 bytes ShieldVerifier.verify takes.
 *
 * @param {{pi_a: Array, pi_b: Array, pi_c: Array}} proof Proof from snarkjs.groth16.prove.
 * @returns {Buffer} A || B || C.
 */
function proofToBytes(proof) {
    return Buffer.concat([g1ToBytes(proof.pi_a), g2ToBytes(proof.pi_b), g1ToBytes(proof.pi_c)]);
}

/**
 * Encodes a snarkjs verification key as ShieldVerifier's VerifyingKey, the argument of its
 * constructor. `ic` holds the constant point and then one point per public input.
 *
 * @param {object} vkey Verification key from `snarkjs zkey export verificationkey`.
 * @returns {{alpha: Buffer, beta: Buffer, gamma: Buffer, delta: Buffer, ic: Buffer[]}}
 */
function verificationKeyToSoroban(vkey) {
    if (vkey.protocol !== "groth16" || vkey.curve !== "bn128") {
        throw new Error(`Expected a Groth16 key over BN254, got ${vkey.protocol} over ${vkey.curve}`);
    }
    if (vkey.IC.length !== vkey.nPublic + 1) {
        throw new Error(`Expected ${vkey.nPublic + 1} IC points, got ${vkey.IC.length}`);
    }
    return {
        alpha: g1ToBytes(vkey.vk_alpha_1),
        beta: g2ToBytes(vkey.vk_beta_2),
        gamma: g2ToBytes(vkey.vk_gamma_2),
        delta: g2ToBytes(vkey.vk_delta_2),
        ic: vkey.IC.map(g1ToBytes),
    };
}

module.exports = {
    BASE_FIELD_SIZE,
    fieldToBytes,
    g1ToBytes,
    g2ToBytes,
    proofToBytes,
    verificationKeyToSoroban,
};
