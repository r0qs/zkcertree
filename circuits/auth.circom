pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "approve.circom";
include "merkleProof.circom";

// Verifies that all grades and tags are included in the credtree and are part
// of authentic commitments in the certree.
// @param n is the maximum number of grades/tags ~= # of credentials
// @param ctl is the level of the certree
// @param cdl is the level of the credential tree
template OffchainAuthCommitments(n, ctl, cdl) {
	signal input grades[n];
	signal input pathGrades[n][cdl];
	signal input pathGradesIndices[n];

	signal input tags[n];
	signal input pathTags[n][cdl];
	signal input pathTagsIndices[n];

	signal input roots[n];
	signal input nullifierHashes[n];

	signal input subjects[n];
	signal input nullifiers[n];
	signal input secrets[n];
	signal input pathCertreeElements[n][ctl];
	signal input pathCertreeIndices[n];

	component certree[n];
	component credtree[2][n];
	component gradeHash[n];
	for (var i = 0; i < n; i++) {
		// Verify wheter the commitment exists in the certree
		certree[i] = Approve(ctl);
		certree[i].root <== roots[i];
		certree[i].nullifierHash <== nullifierHashes[i];
		certree[i].subject <== subjects[i];

		certree[i].nullifier <== nullifiers[i];
		certree[i].secret <== secrets[i];
		certree[i].pathIndices <== pathCertreeIndices[i];
		for (var j = 0; j < ctl; j++) {
			certree[i].pathElements[j] <== pathCertreeElements[i][j];	
    }

		// Compute the grades' hash
		// FIXME: Precise proofs uses h(property_name + value + salt)
		// https://github.com/centrifuge/precise-proofs/blob/93cd509ec264d082ecc352d244b8681a7656dbfa/proofs/tree.go#L763
		gradeHash[i] = Poseidon(1);
		gradeHash[i].inputs[0] <== grades[i];

		// Checks whether grades in the grades vector exists in the correspondent credtree
		credtree[0][i] = MerkleProof(cdl);
		credtree[0][i].leaf <== gradeHash[i].out;
		credtree[0][i].pathIndices <== pathGradesIndices[i];
		for (var j = 0; j < cdl; j++) {
			credtree[0][i].pathElements[j] <== pathGrades[i][j];
		}
		credtree[0][i].root === nullifiers[i];

		// Verify tags vector
		credtree[1][i] = MerkleProof(cdl);
		credtree[1][i].leaf <== tags[i];
		credtree[1][i].pathIndices <== pathTagsIndices[i];
		for (var j = 0; j < cdl; j++) {
			credtree[1][i].pathElements[j] <== pathTags[i][j];
		}
		credtree[1][i].root === nullifiers[i];
	}
}
