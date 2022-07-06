pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "commit.circom";
include "merkleProof.circom";

// Verifies that all grades and tags are included in the credtree and are part
// of authentic commitments in the certree.
// @param n is the maximum number of grades/tags ~= # of credentials
// @param ctl is the level of the certree
// @param cdl is the level of the credential tree
template VerifyCredentialFields(n, ctl, cdl) {
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
	// TODO: use merkle-multiproofs to prove a variable number of leaves in certree/credtree
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
