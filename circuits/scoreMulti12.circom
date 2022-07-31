pragma circom 2.0.4;

include "scoreMulti.circom";

component main {public [root, requiredTags, weights, result]} = ScoreMultiField(2, 5, 4, 12);