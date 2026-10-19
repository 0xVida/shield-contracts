pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "./merkle.circom";
include "./nullifier.circom";

/*
 * ClaimAllocation verifies:
 * 1. The caller knows the secret opening (secret, amount) of a committed allocation.
 * 2. The allocation commitment exists in the Merkle tree with the given root.
 * 3. The nullifierHash is correctly derived from the secret (preventing double-claims).
 * 4. The withdrawal is bound to a specific recipient address (frontrunning protection).
 *
 * Parameters:
 *   levels: Merkle tree depth (e.g. 10 or 20).
 *
 * Public Inputs:
 *   root: Valid Merkle tree root known to the Soroban contract.
 *   nullifierHash: The unique nullifier for this allocation (preventing replay).
 *   recipient: Field element representation of recipient address/key (binds the proof).
 *   amount: Allocation amount being claimed (enforces balance consistency).
 *
 * Private Inputs:
 *   secret: Private secret known only to the recipient.
 *   pathElements[levels]: Sibling hashes along the Merkle inclusion path.
 *   pathIndices[levels]: Direction bits (0 = left, 1 = right) along the path.
 */
template ClaimAllocation(levels) {
    // --- Public Inputs ---
    signal input root;
    signal input nullifierHash;
    signal input recipient;
    signal input amount;

    // --- Private Inputs ---
    signal input secret;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    // 1. Compute Allocation Commitment: leaf = Poseidon(secret, amount)
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== amount;
    signal commitment <== commitmentHasher.out;

    // 2. Verify Merkle Membership in the tree
    component merkleChecker = MerkleTreeInclusionProof(levels);
    merkleChecker.leaf <== commitment;
    merkleChecker.root <== root;
    for (var i = 0; i < levels; i++) {
        merkleChecker.pathElements[i] <== pathElements[i];
        merkleChecker.pathIndices[i] <== pathIndices[i];
    }

    // 3. Derive Nullifier: nullifierHash = Poseidon(TAG, secret, leafIndex)
    component nullifierHasher = NullifierHasher(levels);
    nullifierHasher.secret <== secret;
    for (var i = 0; i < levels; i++) {
        nullifierHasher.pathIndices[i] <== pathIndices[i];
    }
    nullifierHash === nullifierHasher.nullifier;

    // 4. Recipient Authorization Binding:
    // Prevents frontrunning by binding the recipient public signal to the circuit constraints.
    signal recipientSquare;
    recipientSquare <== recipient * recipient;
}

// Default export component for depth 10 (supports up to 1024 allocations per batch/tree)
component main {public [root, nullifierHash, recipient, amount]} = ClaimAllocation(10);
