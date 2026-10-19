/*
 * JS mirror of nullifier.circom, for tests, the SDK and the backend.
 * Any change here must be matched in the circuit, or proofs will not verify.
 */

// Domain tag: ASCII "shieldzk.nullifier" as a field element. Built from the string so
// it is readable; must equal NULLIFIER_DOMAIN() in nullifier.circom (checked by a test).
const NULLIFIER_DOMAIN = BigInt("0x" + Buffer.from("shieldzk.nullifier").toString("hex"));

/**
 * Computes nullifier = Poseidon(NULLIFIER_DOMAIN, secret, leafIndex).
 *
 * @param poseidon  circomlibjs Poseidon instance (from buildPoseidon()).
 * @param secret    The allocation's secret.
 * @param leafIndex The allocation's leaf index in the batch Merkle tree.
 * @returns {bigint} The nullifier as a field element.
 */
function computeNullifier(poseidon, secret, leafIndex) {
    const h = poseidon([NULLIFIER_DOMAIN, BigInt(secret), BigInt(leafIndex)]);
    return BigInt(poseidon.F.toString(h));
}

/**
 * Converts a leaf index to Merkle path direction bits.
 * Same bit order as MerkleTree.getProof: pathIndices[i] is bit i of the index.
 *
 * @param leafIndex The leaf index.
 * @param levels    Merkle tree depth.
 * @returns {number[]} Array of 0/1 bits, least significant first.
 */
function indexToPathIndices(leafIndex, levels) {
    return Array.from({ length: levels }, (_, i) => (leafIndex >> i) & 1);
}

module.exports = { NULLIFIER_DOMAIN, computeNullifier, indexToPathIndices };
