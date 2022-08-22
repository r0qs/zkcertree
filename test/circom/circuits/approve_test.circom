pragma circom 2.0.4;

include "../../../circuits/approve.circom";

// width of tree (2^x) ~= number of credentials
component main {public [root, nullifierHash, sender]} = Approve(8);