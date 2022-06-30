pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "commit.circom";

// Verifies whether a commitment is correctly formed and signed.
template Issue() {
	signal input nullifierHash;
	signal input commitment;
	signal input publicKey[2];

	signal input nullifier;
	signal input secret;
	signal input signature[3];

	component hasher = CommitmentHasher();
	hasher.nullifier <== nullifier;
	hasher.secret <== secret;
	hasher.nullifierHash === nullifierHash;
	hasher.commitment === commitment;

	component verifier = EdDSAPoseidonVerifier();
	verifier.enabled <== 1;
	verifier.M <== hasher.commitment;
	verifier.Ax <== publicKey[0];
	verifier.Ay <== publicKey[1];
	verifier.R8x <== signature[0];
	verifier.R8y <== signature[1];
	verifier.S <== signature[2];
}

component main {public [commitment, nullifierHash, publicKey]} = Issue();