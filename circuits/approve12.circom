pragma circom 2.0.4;

include "approve.circom";

// width of tree (2^x) == number of credentials
component main {public [root, nullifierHash, subject]} = Approve(12);