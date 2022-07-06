pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "commit.circom";

// Verifies whether a commitment is correctly formed and signed.
template Issue() {
	signal input commitment;
	signal input credentialRoot;
	signal input publicKey[2];

	signal input secret;
	signal input signature[3];

	component subject = Subject();
	for (var i = 0; i < 2; i++) {
		subject.publicKey[i] <== publicKey[i];
	}

	component hasher = CommitmentHasher();
	hasher.nullifier <== credentialRoot;
	hasher.subject <== subject.out;
	hasher.secret <== secret;
	hasher.commitment === commitment;

	component verifier = EdDSAPoseidonVerifier();
	verifier.enabled <== 1;
	verifier.M <== hasher.commitment;
	verifier.Ax <== publicKey[0];
	verifier.Ay <== publicKey[1];
	verifier.R8x <== signature[0];
	verifier.R8y <== signature[1];
	verifier.S <== signature[2];
	// TODO: check if subject field in credtree is the correct one (inclusion proof)
}

component main {public [commitment, credentialRoot, publicKey]} = Issue();