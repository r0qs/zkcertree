pragma circom 2.0.4;

include "auth.circom";

component main {public [certreeRoot, nullifierHashes]} = VerifyCredentialFields(5, 12, 12);