pragma circom 2.0.0;

include "./conservation.circom";

// Small version of the conservation circuit for fast tests: depth 3 (8 slots).
component main {public [root, total, batchId]} = Conservation(3);
