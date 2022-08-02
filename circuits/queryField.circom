pragma circom 2.0.4;

include "compare.circom";
include "presentationFieldsAuth.circom";

// Verifies whether a field in a credential met a conditional
// @param `cdl` is the level of the credential tree
// @param `ctl` is the level of the certree
template VerifyConditionalQueryField(cdl, ctl) {
	signal input certreeRoot;
	signal input nullifierHash;
	signal input fieldKey;
	signal input criterion;
	signal input operator;

	signal input field[3];
	signal input pathFieldElements[cdl];
	signal input pathFieldIndices;
	signal input credentialRoot;
	signal input subject;
	signal input secret;
	signal input pathCertreeElements[ctl];
	signal input pathCertreeIndices;

	// Verifies if a field is authentic
	component credAuth = VerifyCredentialField(cdl, ctl);
	credAuth.fieldKey <== fieldKey;
	credAuth.certreeRoot <== certreeRoot;
	credAuth.nullifierHash <== nullifierHash;
	credAuth.pathCertreeIndices <== pathCertreeIndices;
	for(var i = 0; i < ctl; i++) {
		credAuth.pathCertreeElements[i] <== pathCertreeElements[i];
	}
	credAuth.credentialRoot <== credentialRoot;
	credAuth.subject <== subject;
	credAuth.secret <== secret;
	for(var i = 0; i < 3; i++) {
		credAuth.field[i] <== field[i];
	}			
	credAuth.pathFieldIndices <== pathFieldIndices;
	for(var i = 0; i < cdl; i++) {
		credAuth.pathFieldElements[i] <== pathFieldElements[i];
	}

	// Verifies if the criterion met the field value
	component cmp = Compare();
	cmp.a <== field[1];
	cmp.b <== criterion;
	cmp.op <== operator;
	cmp.out === 1;
}

// Verifies whether a field in all credentials met a conditional
// @param `n` is the number of credentials to be verified
// @param `cdl` is the level of the credential tree
// @param `ctl` is the level of the certree
template VerifyConditionalQueryCredentials(n, cdl, ctl) {
	signal input certreeRoot;
	signal input fieldKey;
	signal input criterion;
	signal input operator;

	// TODO: assert max n based on ctl?

	signal input nullifierHashes[n];
	signal input fields[n][3];
	signal input pathFieldElements[n][cdl];
	signal input pathFieldIndices[n];
	signal input credentialRoots[n];
	signal input subjects[n];
	signal input secrets[n];
	signal input pathCertreeElements[n][ctl];
	signal input pathCertreeIndices[n];

	component credAuth[n];
	for(var i = 0; i < n; i++) {
		credAuth[i] = VerifyCredentialField(cdl, ctl);
		credAuth[i].fieldKey <== fieldKey;
		credAuth[i].certreeRoot <== certreeRoot;
		credAuth[i].nullifierHash <== nullifierHashes[i];
		credAuth[i].pathCertreeIndices <== pathCertreeIndices[i];
		for(var j = 0; j < ctl; j++) {
			credAuth[i].pathCertreeElements[j] <== pathCertreeElements[i][j];
		}
		credAuth[i].credentialRoot <== credentialRoots[i];
		credAuth[i].subject <== subjects[i];
		credAuth[i].secret <== secrets[i];
		for(var j = 0; j < 3; j++) {
			credAuth[i].field[j] <== fields[i][j];
		}
		credAuth[i].pathFieldIndices <== pathFieldIndices[i];
		for(var j = 0; j < cdl; j++) {
			credAuth[i].pathFieldElements[j] <== pathFieldElements[i][j];
		}
	}

	// Verifies if the value met the criterion for all credentials
	component cmp[n];
	for (var i = 0; i < n; i++) {
		cmp[i] = Compare();
		cmp[i].a <== fields[i][1];
		cmp[i].b <== criterion;
		cmp[i].op <== operator;
		cmp[i].out === 1;
	}
}
