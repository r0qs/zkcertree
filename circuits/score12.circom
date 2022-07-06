pragma circom 2.0.4;

include "score.circom";

component main {public [root, nullifierHashes, requiredTags, weights, result]} = Score(5, 12, 12);