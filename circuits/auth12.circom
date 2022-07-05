pragma circom 2.0.4;

include "auth.circom";

component main {public [certreeRoot, credentialRoots, nullifierHashes, grades, tags]} = VerifyDisclosedCredentialFields(5, 12, 12);