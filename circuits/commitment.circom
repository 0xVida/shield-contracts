pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";

/*
 * AllocationCommitment computes the commitment (the "sealed envelope") for one allocation.
 *
 * Shared protocol spec (architecture.md, proposed): commitment = Poseidon(amount, secret, batch_id).
 * Every circuit that recomputes a commitment (conservation, withdraw) should use this template,
 * so the circuits can never disagree on the formula or the input order.
 *
 * Inputs:
 *   amount: Allocation amount in token base units.
 *   secret: Random value known to the recipient; hides the amount.
 *   batchId: Batch the allocation belongs to.
 *
 * Output:
 *   commitment: Poseidon(amount, secret, batchId).
 */
template AllocationCommitment() {
    signal input amount;
    signal input secret;
    signal input batchId;

    signal output commitment;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== amount;
    hasher.inputs[1] <== secret;
    hasher.inputs[2] <== batchId;

    commitment <== hasher.out;
}
