pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "commit.circom";
include "merkleProof.circom";
include "credentialTree.circom";

// Verifies that all grades and tags are included in the credtree and are part
// of authentic commitments in the certree.
// @param n is the maximum number of grades/tags ~= # of credentials
// @param ctl is the level of the certree
// @param cdl is the level of the credential tree
template VerifyDisclosedCredentialFields(n, ctl, cdl) {
	signal input certreeRoot;
	signal input credentialRoots[n];
	signal input nullifierHashes[n];
	signal input tags[n][3];
	signal input grades[n][3];

	signal input pathGrades[n][cdl];
	signal input pathGradesIndices[n];
	signal input pathTags[n][cdl];
	signal input pathTagsIndices[n];

	signal input subjects[n];
	signal input blindings[n];
	signal input secrets[n];
	signal input pathCertreeElements[n][ctl];
	signal input pathCertreeIndices[n];

	component certree[n];
	component hasher[n];
	component nullifier[n];
	component credtree[n][2];
	for (var i = 0; i < n; i++) {
		nullifier[i] = Nullifier();
		nullifier[i].root <== credentialRoots[i];
		nullifier[i].blinding <== blindings[i];

		// Verify wheter the commitment exists in the certree
		hasher[i] = CommitmentHasher();
		hasher[i].nullifier <== nullifier[i].out;
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
		credtree[i][0] = CredentialProof(cdl);
		credtree[i][0].property <== grades[i][0];
		credtree[i][0].value <== grades[i][1];
		credtree[i][0].salt <== grades[i][2];
		credtree[i][0].pathIndices <== pathGradesIndices[i];
		for (var j = 0; j < cdl; j++) {
			credtree[i][0].pathElements[j] <== pathGrades[i][j];
		}
		credtree[i][0].root === credentialRoots[i];

		credtree[i][1] = CredentialProof(cdl);
		credtree[i][1].property <== tags[i][0];
		credtree[i][1].value <== tags[i][1];
		credtree[i][1].salt <== tags[i][2];
		credtree[i][1].pathIndices <== pathTagsIndices[i];
		for (var j = 0; j < cdl; j++) {
			credtree[i][1].pathElements[j] <== pathTags[i][j];
		}
		credtree[i][1].root === credentialRoots[i];
	}
}
