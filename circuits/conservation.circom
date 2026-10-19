pragma circom 2.0.0;

include "node_modules/circomlib/circuits/bitify.circom";
include "node_modules/circomlib/circuits/poseidon.circom";
include "./commitment.circom";

/*
 * MerkleRootFromLeaves hashes 2^levels leaves into a single root.
 * It builds the same tree as lib/merkleTree.js: binary, parent = Poseidon(left, right).
 *
 * All nodes live in one array. Leaves fill nodes[0 .. numLeaves-1], and parent k is
 * stored at nodes[numLeaves + k] with children nodes[2k] and nodes[2k+1]. For 4 leaves:
 *
 *            nodes[6]          <- root
 *           /        \
 *      nodes[4]    nodes[5]
 *      /    \      /    \
 *     n[0] n[1]  n[2]  n[3]    <- leaves
 *
 * Parameters:
 *   levels: Depth of the tree (2^levels leaves).
 *
 * Inputs:
 *   leaves[2^levels]: Leaf values in index order.
 *
 * Output:
 *   root: The Merkle root.
 */
template MerkleRootFromLeaves(levels) {
    var numLeaves = 1 << levels;

    signal input leaves[numLeaves];
    signal output root;

    signal nodes[2 * numLeaves - 1];
    component hashers[numLeaves - 1];

    for (var i = 0; i < numLeaves; i++) {
        nodes[i] <== leaves[i];
    }

    for (var k = 0; k < numLeaves - 1; k++) {
        hashers[k] = Poseidon(2);
        hashers[k].inputs[0] <== nodes[2 * k];
        hashers[k].inputs[1] <== nodes[2 * k + 1];
        nodes[numLeaves + k] <== hashers[k].out;
    }

    root <== nodes[2 * numLeaves - 2];
}

/*
 * Conservation proves, for one batch, that every allocation committed under `root`
 * has a valid 64-bit amount and that the amounts add up to exactly `total`.
 *
 * The tree has 2^levels slots. A slot is either active (a real allocation, whose leaf is
 * its commitment) or empty (leaf 0, as the spec requires). Every active slot's amount is
 * counted, so the batch cannot hold an allocation that is missing from the total.
 *
 * Parameters:
 *   levels: Merkle tree depth (2^levels slots).
 *
 * Public Inputs:
 *   root: Merkle root of the batch, stored by the vault.
 *   total: Amount deposited for the batch, in token base units.
 *   batchId: Batch identifier; every commitment is bound to it.
 *
 * Private Inputs:
 *   amounts[2^levels]: Allocation amount per slot (0 for empty slots).
 *   secrets[2^levels]: Recipient secret per slot (ignored for empty slots).
 *   active[2^levels]: 1 for a real allocation, 0 for an empty slot.
 */
template Conservation(levels) {
    var numSlots = 1 << levels;

    // --- Public Inputs ---
    signal input root;
    signal input total;
    signal input batchId;

    // --- Private Inputs ---
    signal input amounts[numSlots];
    signal input secrets[numSlots];
    signal input active[numSlots];

    component rangeChecks[numSlots];
    component commitments[numSlots];
    component tree = MerkleRootFromLeaves(levels);

    var sum = 0;

    for (var i = 0; i < numSlots; i++) {
        // 1. Each slot is either active (1) or empty (0).
        active[i] * (active[i] - 1) === 0;

        // 2. Range check: the amount fits in 64 bits. Circuit arithmetic wraps around at a
        //    ~254-bit prime p, so without this check an amount of p - 20 would act like -20
        //    and let the other allocations add up to more than the deposit.
        rangeChecks[i] = Num2Bits(64);
        rangeChecks[i].in <== amounts[i];

        // 3. Empty slots carry no money.
        (1 - active[i]) * amounts[i] === 0;

        // 4. The leaf is the allocation's commitment, or 0 for an empty slot.
        commitments[i] = AllocationCommitment();
        commitments[i].amount <== amounts[i];
        commitments[i].secret <== secrets[i];
        commitments[i].batchId <== batchId;
        tree.leaves[i] <== active[i] * commitments[i].commitment;

        sum += amounts[i];
    }

    // 5. The leaves hash to the public root, so the proof is about exactly this batch.
    root === tree.root;

    // 6. Balance conservation: the allocations add up to the deposited total.
    //    Each amount is below 2^64 and there are at most 2^levels of them, so the sum
    //    stays far below p and cannot wrap around.
    total === sum;
}
