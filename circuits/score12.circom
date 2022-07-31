pragma circom 2.0.4;

include "score.circom";

component main {public [root, requiredTags, weights, result]} = Score(5, 4, 12);