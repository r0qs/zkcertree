pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/comparators.circom";
include "commit.circom";
include "dot.circom";
include "presentationFieldsAuth.circom";

// Verifies whether the inner product of the grades field of credentials is the given one.
// It also checks if the course tags met the required tags.
// And it checks if the grades and tags fields exists in the certree by transitivity
// i.e. if they exists in the credential root of the respective credential and if the credential
// root exists in the given certree root.
// ctl is the certree level
// cdl is the credential tree level
// n is the number of credentials in the certree that is being checked
template Score(n, cdl, ctl) {
	signal input root;
	signal input requiredTags[n];
	signal input weights[n];
	signal input result;

	signal input nullifierHashes[n];
	signal input tags[n][3];
	signal input pathTags[n][cdl];
	signal input pathTagsIndices[n];
	signal input grades[n][3];
	signal input pathGrades[n][cdl];
	signal input pathGradesIndices[n];
	signal input credentialRoots[n];
	signal input subjects[n];
	signal input secrets[n];
	signal input pathCertreeElements[n][ctl];
	signal input pathCertreeIndices[n];

	signal output out;

	// FIXME: update to new VerifyCredentialField
	component auth = VerifyCredentialFields(n, cdl, ctl);
	component tagsHasher[n];
	component gradesHasher[n];
	component sameTags[n];
	auth.certreeRoot <== root;
	for(var i = 0; i < n; i++) {
		auth.credentialRoots[i] <== credentialRoots[i];
		auth.nullifierHashes[i] <== nullifierHashes[i];

		auth.subjects[i] <== subjects[i];
		auth.secrets[i] <== secrets[i];
		auth.pathCertreeIndices[i] <== pathCertreeIndices[i];
		for(var j = 0; j < ctl; j++) {
			auth.pathCertreeElements[i][j] <== pathCertreeElements[i][j];
		}

		// ensure tags match 
		sameTags[i] = IsEqual();
		sameTags[i].in[0] <== requiredTags[i];
		sameTags[i].in[1] <== tags[i][1];
		sameTags[i].out === 0;

		tagsHasher[i] = CredentialLeafHasher();
		tagsHasher[i].key <== tags[i][0];
		tagsHasher[i].value <== tags[i][1];
		tagsHasher[i].salt <== tags[i][2];
		auth.tagsHash[i] <== tagsHasher[i].out;
		
		auth.pathTagsIndices[i] <== pathTagsIndices[i];
		for(var j = 0; j < cdl; j++) {
			auth.pathTags[i][j] <== pathTags[i][j];
		}

		gradesHasher[i] = CredentialLeafHasher();
		gradesHasher[i].key <== grades[i][0];
		gradesHasher[i].value <== grades[i][1];
		gradesHasher[i].salt <== grades[i][2];
		auth.gradesHash[i] <== gradesHasher[i].out;

		auth.pathGradesIndices[i] <== pathGradesIndices[i];
		for(var j = 0; j < cdl; j++) {
			auth.pathGrades[i][j] <== pathGrades[i][j];
		}
	}

	component dot = DotProduct(n);
	for (var i = 0; i < n; i++) {
		dot.a[i] <== grades[i][1];
		dot.b[i] <== weights[i];
	}
	dot.out === result;
}
