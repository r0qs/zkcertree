pragma circom 2.0.4;

include "auth.circom";

component main {public [roots, nullifierHashes, subjects, tags]} = OffchainAuthCommitments(5, 12, 12); 