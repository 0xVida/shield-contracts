pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";

/*
 * Domain tag for nullifiers: the ASCII bytes of "shieldzk.nullifier" as a field element.
 *
 *   73 68 69 65 6c 64 7a 6b 2e 6e 75 6c 6c 69 66 69 65 72
 *    s  h  i  e  l  d  z  k  .  n  u  l  l  i  f  i  e  r
 *
 * Why a tag: without it, Poseidon(secret, leafIndex) has the same shape as the
 * commitment Poseidon(secret, amount), so an allocation whose amount equals its leaf
 * index would get nullifier == commitment and reveal which leaf it owns. The tag is
 * 143 bits and amounts are range-limited to 64 bits, so no commitment input can match it.
 *
 * Must stay identical to NULLIFIER_DOMAIN in lib/nullifier.js (checked by a test).
 */
function NULLIFIER_DOMAIN() {
    return 0x736869656c647a6b2e6e756c6c6966696572;
}

/*
 * LeafIndex rebuilds the leaf index from the Merkle path direction bits.
 *
 * Parameters:
 *   levels: Merkle tree depth.
 *
 * Inputs:
 *   pathIndices[levels]: Direction bits, where pathIndices[i] is bit i of the index
 *                        (0 = left child, 1 = right child). Same convention as
 *                        MerkleProof in merkle.circom and lib/merkleTree.js.
 *
 * Output:
 *   out: leafIndex = sum(pathIndices[i] * 2^i).
 */
template LeafIndex(levels) {
    signal input pathIndices[levels];
    signal output out;

    var acc = 0;
    var pow = 1;
    for (var i = 0; i < levels; i++) {
        // Enforce binary bits here too, so this template is sound even when used
        // without MerkleProof (a non-bit would let one leaf map to many indices).
        pathIndices[i] * (1 - pathIndices[i]) === 0;
        acc += pathIndices[i] * pow;
        pow *= 2;
    }
    out <== acc;
}

/*
 * NullifierHasher derives the nullifier for an allocation:
 *
 *   nullifier = Poseidon(NULLIFIER_DOMAIN, secret, leafIndex)
 *
 * - secret ties the nullifier to the allocation. The caller must wire the same
 *   `secret` signal used to build the commitment; that shared signal is what binds
 *   the nullifier to the allocation proven in the Merkle tree.
 * - leafIndex makes nullifiers unique per leaf, even if two allocations share a secret.
 * - NULLIFIER_DOMAIN keeps nullifiers from colliding with commitments (see above).
 *
 * Parameters:
 *   levels: Merkle tree depth.
 *
 * Inputs:
 *   secret: The allocation's private secret.
 *   pathIndices[levels]: Merkle path direction bits for the allocation's leaf.
 *
 * Output:
 *   nullifier: Value published on-chain to mark the allocation as claimed.
 */
template NullifierHasher(levels) {
    signal input secret;
    signal input pathIndices[levels];
    signal output nullifier;

    // 1. Recover the leaf index from the path bits
    component index = LeafIndex(levels);
    for (var i = 0; i < levels; i++) {
        index.pathIndices[i] <== pathIndices[i];
    }

    // 2. Hash tag, secret and index together
    component hasher = Poseidon(3);
    hasher.inputs[0] <== NULLIFIER_DOMAIN();
    hasher.inputs[1] <== secret;
    hasher.inputs[2] <== index.out;
    nullifier <== hasher.out;
}
