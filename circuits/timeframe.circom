pragma circom 2.0.4;

include "compare.circom";
include "presentationFieldsAuth.circom";

// TimeframeProof verifies for all n credentials whether they are present in the certree
// and if the total issuance period satisfies the given condition
// @param `n` is the number of credentials to be verified
// @param `cdl` is the level of the credential tree
// @param `ctl` is the level of the certree
template TimeframeProof(n, cdl, ctl) {
	assert(n > 0 && n <= (1 << ctl));

	signal input certreeRoot;
	signal input nullifierHashes[n];
	signal input timestampFieldKey;
	signal input period;
	signal input operator;

	signal input fields[n][3];
	signal input pathFieldElements[n][cdl];
	signal input pathFieldIndices[n];
	signal input credentialRoots[n];
	signal input subjects[n];
	signal input secrets[n];
	signal input pathCertreeElements[n][ctl];
	signal input pathCertreeIndices[n];

	signal output duration;

	component credAuth[n];
	for(var i = 0; i < n; i++) {
		credAuth[i] = VerifyCredentialField(cdl, ctl);
		credAuth[i].fieldKey <== timestampFieldKey;
		credAuth[i].certreeRoot <== certreeRoot;
		credAuth[i].nullifierHash <== nullifierHashes[i];

		for(var j = 0; j < 3; j++) {
			credAuth[i].field[j] <== fields[i][j];
		}
		for (var j = 0; j < cdl; j++) {
			credAuth[i].pathFieldElements[j] <== pathFieldElements[i][j];
		}
		credAuth[i].pathFieldIndices <== pathFieldIndices[i];
		credAuth[i].credentialRoot <== credentialRoots[i];
		credAuth[i].subject <== subjects[i];
		credAuth[i].secret <== secrets[i];
		credAuth[i].pathCertreeIndices <== pathCertreeIndices[i];
		for(var j = 0; j < ctl; j++) {
			credAuth[i].pathCertreeElements[j] <== pathCertreeElements[i][j];
		}
	}

	// ensures incremental timestamp constraint and total duration (i.e. t[n-1]-t[0])
	var totalDuration = 0;
	for (var i = 0; i < n-1; i++) {
		var d = fields[i+1][1] - fields[i][1];
		assert(d > 0);
		totalDuration += d;
	}
	totalDuration === fields[n-1][1] - fields[0][1];
	
	component cmp = Compare();
	cmp.a <== totalDuration;
	cmp.b <== period;
	cmp.op <== operator;
	cmp.out === 1;

	totalDuration ==> duration;
}