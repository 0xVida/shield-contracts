pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";
include "./nullifier.circom";

/*
 * NullifierBinding is a test harness proving that the commitment and the nullifier
 * come from the same secret. Used by test/nullifier.test.js only; the production
 * circuit is claim.circom.
 *
 * The commitment formula mirrors claim.circom (Poseidon(secret, amount)) and should
 * follow whatever the shared protocol spec settles on.
 *
 * Parameters:
 *   levels: Merkle tree depth.
 *
 * Public Inputs:
 *   commitment: The allocation commitment (private in claim.circom, where it is
 *               proven via the Merkle tree; public here so tests can target it).
 *   nullifierHash: The claimed nullifier.
 *
 * Private Inputs:
 *   secret: The allocation's secret, shared by the commitment and nullifier.
 *   amount: The allocation amount.
 *   pathIndices[levels]: Merkle path direction bits for the allocation's leaf.
 */
template NullifierBinding(levels) {
    // --- Public Inputs ---
    signal input commitment;
    signal input nullifierHash;

    // --- Private Inputs ---
    signal input secret;
    signal input amount;
    signal input pathIndices[levels];

    // 1. The secret must open the commitment
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== amount;
    commitment === commitmentHasher.out;

    // 2. The nullifier must be derived from that same secret
    component nullifierHasher = NullifierHasher(levels);
    nullifierHasher.secret <== secret;
    for (var i = 0; i < levels; i++) {
        nullifierHasher.pathIndices[i] <== pathIndices[i];
    }
    nullifierHash === nullifierHasher.nullifier;
}

// Depth 4 (16 leaves) keeps tests fast
component main {public [commitment, nullifierHash]} = NullifierBinding(4);
