pragma circom 2.0.0;

include "./conservation.circom";

component main {public [root, total, batchId]} = Conservation(8);
