pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "commit.circom";
include "merkleProof.circom";

// Verifies the authenticity of a credential presentation
template VerifyPresentation(levels) {
	signal input certreeRoot;
	signal input credentialRoot;
	signal input nullifierHash;
	signal input publicKey[2];

	signal input blinding;
	signal input secret;
	signal input pathElements[levels];
	signal input pathIndices;
	signal input signature[3];

	component nullifier = Nullifier();
	nullifier.root <== credentialRoot;
	nullifier.blinding <== blinding;

	component subject = Subject();
	for (var i = 0; i < 2; i++) {
		subject.publicKey[i] <== publicKey[i];
	}

	component hasher = CommitmentHasher();
	hasher.nullifier <== nullifier.out;
	hasher.subject <== subject.out;
	hasher.secret <== secret;
	hasher.nullifierHash === nullifierHash;

	component verifier = EdDSAPoseidonVerifier();
	verifier.enabled <== 1;
	verifier.M <== hasher.commitment;
	verifier.Ax <== publicKey[0];
	verifier.Ay <== publicKey[1];
	verifier.R8x <== signature[0];
	verifier.R8y <== signature[1];
	verifier.S <== signature[2];

	component tree = MerkleProof(levels);
	tree.leaf <== hasher.commitment;
	tree.pathIndices <== pathIndices;
	for (var i = 0; i < levels; i++) {
		tree.pathElements[i] <== pathElements[i];
	}
	tree.root === certreeRoot;
}
