pragma circom 2.0.4;

include "presentationFieldsAuth.circom";

component main {public [certreeRoot, nullifierHashes]} = VerifyCredentialFields(5, 12, 12);