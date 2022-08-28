pragma circom 2.0.4;

include "../../../circuits/score.circom";

component main {public [certreeRoot, requiredTags, weights, result]} = Score(0, 1, 5, 3, 8);