pragma circom 2.0.0;

include "./commitment.circom";
include "./nullifier.circom";

// Test-only binding between the allocation commitment and its nullifier.
template NullifierBinding(levels) {
    signal input commitment;
    signal input nullifierHash;

    signal input secret;
    signal input amount;
    signal input batchId;
    signal input pathIndices[levels];

    component commitmentHasher = AllocationCommitment();
    commitmentHasher.amount <== amount;
    commitmentHasher.secret <== secret;
    commitmentHasher.batchId <== batchId;
    commitment === commitmentHasher.commitment;

    component nullifierHasher = NullifierHasher(levels);
    nullifierHasher.secret <== secret;
    for (var i = 0; i < levels; i++) {
        nullifierHasher.pathIndices[i] <== pathIndices[i];
    }
    nullifierHash === nullifierHasher.nullifier;
}

// Depth 4 (16 leaves) keeps tests fast
component main {public [commitment, nullifierHash]} = NullifierBinding(4);
