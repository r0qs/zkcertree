pragma circom 2.0.4;

include "presentationAuth.circom";

component main {public [certreeRoot, credentialRoot, nullifierHash, publicKey]} = PresentationAuth(12);