pragma circom 2.0.4;

include "../../../circuits/timeframe.circom";

component main {public [certreeRoot, nullifierHashes, timestampFieldKey, period, operator]} = TimeframeProof(5, 3, 8);