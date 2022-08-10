pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/comparators.circom";
include "dot.circom";
include "presentationFieldsAuth.circom";

// Verifies whether all credentials exists in the certree and
// that each credential's field exists in the correspondent credential tree using merkle multiproof
// @param `tagIdx` is the index of the tag Field in the credential
// @param `gradeIdx` is the index of the grade Field in the credential
// @param `m` is the number of leaves/fields to be proved in each credential tree (precise-proof)
// @param `n` is the number of credentials to be verified
// @param `cdl` is the level of the credential tree
// @param `ctl` is the level of the certree
// Note:
// - each leave of the certree contains a commitment to a credential tree root
// - currently m must be the same for all credentials in the certree
// - each leave of a credential tree has 3 fields: key, value and salt
template Score(tagIdx, gradeIdx, m, n, cdl, ctl) {
	assert(m > 1);

	signal input certreeRoot;
	signal input requiredTags[n];
	signal input weights[n];
	signal input result;

	signal input nullifierHashes[n];
	signal input fields[n][m][3];
	signal input pathFieldElements[n][m];
	signal input fieldIndices[n][m];
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
		credAuth[i].certreeRoot <== certreeRoot;
		credAuth[i].nullifierHash <== nullifierHashes[i];

		// ensure tags match 
		sameTags[i] = IsEqual();
		sameTags[i].in[0] <== requiredTags[i];
		sameTags[i].in[1] <== fields[i][tagIdx][1];
		sameTags[i].out === 1;

		for(var j = 0; j < m; j++) {
			for(var k = 0; k < 3; k++) {
				credAuth[i].fields[j][k] <== fields[i][j][k];
			}
			credAuth[i].fieldIndices[j] <== fieldIndices[i][j];
			credAuth[i].pathFieldElements[j] <== pathFieldElements[i][j];
		}

		credAuth[i].credentialRoot <== credentialRoots[i];
		credAuth[i].subject <== subjects[i];
		credAuth[i].secret <== secrets[i];
		credAuth[i].pathCertreeIndices <== pathCertreeIndices[i];
		for(var j = 0; j < ctl; j++) {
			credAuth[i].pathCertreeElements[j] <== pathCertreeElements[i][j];
		}
	}

	component dot = DotProduct(n);
	for (var i = 0; i < n; i++) {
		dot.a[i] <== fields[i][gradeIdx][1];
		dot.b[i] <== weights[i];
		//FIXME: we must also range check each intermediary result to ensure that the sum does not wrap around.
	}
	dot.out === result;
}
