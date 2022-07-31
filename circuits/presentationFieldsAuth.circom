pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "commit.circom";
include "merkleProof.circom";

// Verifies that all grades and tags are included in the credtree and are part
// of authentic commitments in the certree.
// @param n is the maximum number of credentials
// @param ctl is the level of the certree
// @param cdl is the level of the credential tree
template VerifyCredentialFields(n, cdl, ctl) {
	signal input certreeRoot;
	signal input nullifierHashes[n];

	signal input tagsHash[n];
	signal input pathTags[n][cdl];
	signal input pathTagsIndices[n];
	signal input gradesHash[n];
	signal input pathGrades[n][cdl];
	signal input pathGradesIndices[n];

	signal input credentialRoots[n];
	signal input subjects[n];
	signal input secrets[n];
	signal input pathCertreeElements[n][ctl];
	signal input pathCertreeIndices[n];

	component certree[n];
	component hasher[n];
	component credtree[n][2];
	for (var i = 0; i < n; i++) {
		// Verify wheter the commitment exists in the certree
		hasher[i] = CommitmentHasher();
		hasher[i].nullifier <== credentialRoots[i];
		hasher[i].subject <== subjects[i];
		hasher[i].secret <== secrets[i];
		hasher[i].nullifierHash === nullifierHashes[i];

		certree[i] = MerkleProof(ctl);
		certree[i].leaf <== hasher[i].commitment;
		certree[i].pathIndices <== pathCertreeIndices[i];
		for (var j = 0; j < ctl; j++) {
			certree[i].pathElements[j] <== pathCertreeElements[i][j];	
    }
		certree[i].root === certreeRoot;

		// Verify grade and tag fields in the credential tree
		credtree[i][0] = MerkleProof(cdl);
		credtree[i][0].leaf <== gradesHash[i];
		credtree[i][0].pathIndices <== pathGradesIndices[i];
		for (var j = 0; j < cdl; j++) {
			credtree[i][0].pathElements[j] <== pathGrades[i][j];
		}
		credtree[i][0].root === credentialRoots[i];

		credtree[i][1] = MerkleProof(cdl);
		credtree[i][1].leaf <== tagsHash[i];
		credtree[i][1].pathIndices <== pathTagsIndices[i];
		for (var j = 0; j < cdl; j++) {
			credtree[i][1].pathElements[j] <== pathTags[i][j];
		}
		credtree[i][1].root === credentialRoots[i];
	}
}

// Verifies that up to n fields are included in the credtree and are part
// of authentic commitments in the certree.
// @param ctl is the level of the certree
// @param cdl is the level of the credential tree
template VerifyCredentialMultiField(cdl, ctl) {
	signal input certreeRoot;
	signal input nullifierHash;

	var n = 1 << cdl;
	signal input credentialFields[n][3];
	signal input credentialFieldsPath[n];
	signal input credentialFieldsIndices[n];

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
	component fieldHasher[n];
	component credtree = MerkleMultiProof(cdl);
	for (var i = 0; i < n; i++) {
		fieldHasher[i] = CredentialLeafHasher();
		fieldHasher[i].key <== credentialFields[i][0];
		fieldHasher[i].value <== credentialFields[i][1];
		fieldHasher[i].salt <== credentialFields[i][2];
		credtree.leaves[i] <== fieldHasher[i].out;
		credtree.pathElements[i] <== credentialFieldsPath[i];
		credtree.leafIndices[i] <== credentialFieldsIndices[i];
	}
	credtree.root === credentialRoot;
}