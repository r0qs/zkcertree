pragma circom 2.0.4;

include "presentationAuth.circom";

component main {public [certreeRoot, nullifierHash, publicKey]} = PresentationAuth(12);