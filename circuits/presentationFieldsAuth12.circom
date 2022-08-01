pragma circom 2.0.4;

include "presentationFieldsAuth.circom";

component main {public [fieldKey, certreeRoot, nullifierHash]} = VerifyCredentialField(5, 12);