pragma circom 2.0.4;

include "score.circom";

component main {public [certreeRoot, requiredTags, weights, result]} = Score(0, 1, 2, 5, 4, 12);