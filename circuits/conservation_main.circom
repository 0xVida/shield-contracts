pragma circom 2.0.0;

include "./conservation.circom";

// Production circuit: depth 10 (1024 allocations per batch), per the proposed spec.
// Public signals, in order: root, total, batchId.
component main {public [root, total, batchId]} = Conservation(10);
