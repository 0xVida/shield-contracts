pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/switcher.circom";

/*
 * MerkleProof verifies that a given leaf belongs to a Merkle tree with a given root.
 *
 * Parameters:
 *   levels: The depth of the Merkle tree (e.g. 10 or 20).
 *
 * Inputs:
 *   leaf: The leaf element whose membership is being proved.
 *   pathElements[levels]: The sibling hashes along the Merkle path.
 *   pathIndices[levels]: Direction bits (0 = current node is left child, 1 = right child).
 *
 * Output:
 *   root: The calculated root of the Merkle tree.
 */
template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    signal output root;

    signal currentHash[levels + 1];
    currentHash[0] <== leaf;

    component switchers[levels];
    component hashers[levels];

    for (var i = 0; i < levels; i++) {
        // Enforce that pathIndices[i] is strictly binary (0 or 1)
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // Switcher takes sel, L, R
        // If sel == 0: outL = L, outR = R
        // If sel == 1: outL = R, outR = L
        switchers[i] = Switcher();
        switchers[i].sel <== pathIndices[i];
        switchers[i].L <== currentHash[i];
        switchers[i].R <== pathElements[i];

        // Hash the ordered children using Poseidon(2)
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        currentHash[i + 1] <== hashers[i].out;
    }

    root <== currentHash[levels];
}

/*
 * MerkleTreeInclusionProof asserts that the leaf is part of a Merkle tree
 * with the specified public root.
 */
template MerkleTreeInclusionProof(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component proof = MerkleProof(levels);
    proof.leaf <== leaf;
    for (var i = 0; i < levels; i++) {
        proof.pathElements[i] <== pathElements[i];
        proof.pathIndices[i] <== pathIndices[i];
    }

    // Assert that the computed root matches the claimed public root
    root === proof.root;
}
