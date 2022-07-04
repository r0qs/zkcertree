pragma circom 2.0.4;

include "verify.circom";

component main {public [certreeRoot, credentialRoot, publicKey]} = VerifyPresentation(12);