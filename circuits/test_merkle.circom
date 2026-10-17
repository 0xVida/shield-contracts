pragma circom 2.0.0;

include "./merkle.circom";

component main {public [leaf]} = MerkleProof(4);
