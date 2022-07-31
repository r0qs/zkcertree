pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/comparators.circom";
include "commit.circom";
include "dot.circom";
include "presentationFieldsAuth.circom";

// Verifies whether all credentials exists in the certree and
// that each credential's field exists in the correspondent credential tree using merkle multiproof
// ctl is the certree level
// cdl is the credential tree level
// n is the number of credentials in the certree that is being checked
// each leave of the certree contains a commitment to a credential tree root
// m is the number of leaves (i.e. fields) in each credential tree (precise-proof)
// Currently m must be the same for all credentials.
// Each leave of a credential tree has 3 fields: key, value and salt
template ScoreMultiField(m, n, cdl, ctl) {
	assert(m > 1);
	// tagIdx is the index of the tag Field in credentialFields
	var tagIdx = 0;
	// valueIdx is the index of the grade Field in credentialFields
	var valueIdx = 1;

	signal input root;
	signal input requiredTags[n];
	signal input weights[n];
	signal input result;

	signal input nullifierHashes[n];
	signal input credentialFields[n][m][3];
	signal input credentialFieldsPath[n][m];
	signal input credentialFieldsIndices[n][m];
	signal input credentialRoots[n];
	signal input subjects[n];
	signal input secrets[n];
	signal input pathCertreeElements[n][ctl];
	signal input pathCertreeIndices[n];

	signal output out;

	component credAuth[n];
	component sameTags[n];
	signal tag;
	for(var i = 0; i < n; i++) {
		credAuth[i] = VerifyCredentialMultiField(cdl,ctl);
		credAuth[i].certreeRoot <== root;
		credAuth[i].credentialRoot <== credentialRoots[i];
		credAuth[i].nullifierHash <== nullifierHashes[i];

		credAuth[i].subject <== subjects[i];
		credAuth[i].secret <== secrets[i];
		credAuth[i].pathCertreeIndices <== pathCertreeIndices[i];
		for(var j = 0; j < ctl; j++) {
			credAuth[i].pathCertreeElements[j] <== pathCertreeElements[i][j];
		}

		// ensure tags match 
		sameTags[i] = IsEqual();
		sameTags[i].in[0] <== requiredTags[i];
		sameTags[i].in[1] <== credentialFields[i][tagIdx][1];
		sameTags[i].out === 0;

		for(var j = 0; j < m; j++) {
			for(var k = 0; k < 3; k++) {
				credAuth[i].credentialFields[j][k] <== credentialFields[i][j][k];
			}			
			credAuth[i].credentialFieldsIndices[j] <== credentialFieldsIndices[i][j];
			credAuth[i].credentialFieldsPath[j] <== credentialFieldsPath[i][j];
		}
	}

	component dot = DotProduct(n);
	signal value;
	for (var i = 0; i < n; i++) {
		dot.a[i] <== credentialFields[i][valueIdx][1];
		dot.b[i] <== weights[i];
	}
	dot.out === result;
}
