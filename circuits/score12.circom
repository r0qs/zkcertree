pragma circom 2.0.4;

include "score.circom";

component main {public [roots, nullifierHashes, tags, weights, result]} = Score(5, 12, 12);