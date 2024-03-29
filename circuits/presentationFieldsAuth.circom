pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/comparators.circom";
include "commit.circom";
include "merkleProof.circom";

// Verifies if a crendential's field is included in the credtree and
// if it has an authentic commitment in the certree.
// @param `cdl` is the level of the credential tree
// @param `ctl` is the level of the certree
template VerifyCredentialField(cdl, ctl) {
	signal input fieldKey;
	signal input certreeRoot;
	signal input nullifierHash;

	signal input field[3];
	signal input pathFieldElements[cdl];
	signal input pathFieldIndices;
	signal input credentialRoot;
	signal input subject;
	signal input secret;
	signal input pathCertreeElements[ctl];
	signal input pathCertreeIndices;

	// Verify commitment
	component commHasher = CommitmentHasher();
	commHasher.nullifier <== credentialRoot;
	commHasher.subject <== subject;
	commHasher.secret <== secret;
	commHasher.nullifierHash === nullifierHash;

	// Verify whether the commitment exists in the certree
	component certree;
	certree = MerkleProof(ctl);
	certree.leaf <== commHasher.commitment;
	certree.pathIndices <== pathCertreeIndices;
	for (var j = 0; j < ctl; j++) {
		certree.pathElements[j] <== pathCertreeElements[j];
	}
	certree.root === certreeRoot;

	component eq = IsEqual();
	eq.in[0] <== fieldKey;
	eq.in[1] <== field[0];
	// Assert keys match
	eq.out === 1;

	component fieldHasher = CredentialLeafHasher();
	fieldHasher.key <== field[0];
	fieldHasher.value <== field[1];
	fieldHasher.salt <== field[2];

	// Verify whether the value exists in the credential tree
	component credtree = MerkleProof(cdl);
	credtree.leaf <== fieldHasher.out;
	credtree.pathIndices <== pathFieldIndices;
	for (var j = 0; j < cdl; j++) {
		credtree.pathElements[j] <== pathFieldElements[j];
	}
	credtree.root === credentialRoot;
}

// Verifies that up to n fields are included in the credtree and are part
// of authentic commitments in the certree.
// @param `cdl` is the level of the credential tree
// @param `ctl` is the level of the certree
// TODO: receive credential schema root and check against field keys.
template VerifyCredentialMultiField(cdl, ctl) {
	signal input certreeRoot;
	signal input nullifierHash;

	var m = 1 << cdl;
	signal input fields[m][3];
	signal input pathFieldElements[m];
	signal input fieldIndices[m];

	signal input credentialRoot;
	signal input subject;
	signal input secret;
	signal input pathCertreeElements[ctl];
	signal input pathCertreeIndices;

	// Verify whether the commitment exists in the certree
	component commitHasher = CommitmentHasher();
	commitHasher.nullifier <== credentialRoot;
	commitHasher.subject <== subject;
	commitHasher.secret <== secret;
	commitHasher.nullifierHash === nullifierHash;

	// TODO: use one multiproof for both trees
	// "one proof to rule them all!"
	component certree = MerkleProof(ctl);
	certree.leaf <== commitHasher.commitment;
	certree.pathIndices <== pathCertreeIndices;
	for (var i = 0; i < ctl; i++) {
		certree.pathElements[i] <== pathCertreeElements[i];
	}
	certree.root === certreeRoot;

	// Verify whether the fields exists in the credential tree
	component fieldHasher[m];
	component zero[m];
	component credtree = MerkleMultiProof(cdl);
	signal s[m];
	for (var i = 0; i < m; i++) {
		zero[i] = IsZero();
		zero[i].in <== fields[i][0];
		s[i] <== 1 - zero[i].out;

		fieldHasher[i] = CredentialLeafHasher();
		fieldHasher[i].key <== fields[i][0];
		fieldHasher[i].value <== fields[i][1];
		fieldHasher[i].salt <== fields[i][2];

		credtree.leaves[i] <== (fieldHasher[i].out)*s[i];
		credtree.pathElements[i] <== pathFieldElements[i];
		credtree.leafIndices[i] <== fieldIndices[i];
	}
	credtree.root === credentialRoot;
}