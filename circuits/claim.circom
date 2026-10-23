pragma circom 2.0.0;

include "./merkle.circom";
include "./nullifier.circom";
include "./commitment.circom";

/*
 * Proves membership of an allocation commitment and binds its nullifier and
 * recipient to the same claim.
 */
template ClaimAllocation(levels) {
    signal input root;
    signal input nullifierHash;
    signal input recipient;
    signal input amount;

    signal input secret;
    signal input batchId;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component commitmentHasher = AllocationCommitment();
    commitmentHasher.amount <== amount;
    commitmentHasher.secret <== secret;
    commitmentHasher.batchId <== batchId;
    signal commitment <== commitmentHasher.commitment;

    component merkleChecker = MerkleTreeInclusionProof(levels);
    merkleChecker.leaf <== commitment;
    merkleChecker.root <== root;
    for (var i = 0; i < levels; i++) {
        merkleChecker.pathElements[i] <== pathElements[i];
        merkleChecker.pathIndices[i] <== pathIndices[i];
    }

    component nullifierHasher = NullifierHasher(levels);
    nullifierHasher.secret <== secret;
    for (var i = 0; i < levels; i++) {
        nullifierHasher.pathIndices[i] <== pathIndices[i];
    }
    nullifierHash === nullifierHasher.nullifier;

    // Keep recipient in the constrained public statement.
    signal recipientSquare;
    recipientSquare <== recipient * recipient;
}

component main {public [root, nullifierHash, recipient, amount]} = ClaimAllocation(10);
