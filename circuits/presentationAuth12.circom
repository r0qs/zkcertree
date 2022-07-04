pragma circom 2.0.4;

include "presentationAuth.circom";

component main {public [certreeRoot, credentialRoot, publicKey]} = PresentationAuth(12);