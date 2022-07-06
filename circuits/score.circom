pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/comparators.circom";
include "commit.circom";
include "auth.circom";

template Score(n, ctl, cdl) {
	signal input root;
	signal input nullifierHashes[n];
	signal input requiredTags[n];
	signal input weights[n];
	signal input result;

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

	component auth = VerifyCredentialFields(n, ctl, cdl);
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
		tagsHasher[i].property <== tags[i][0];
		tagsHasher[i].value <== tags[i][1];
		tagsHasher[i].salt <== tags[i][2];
		auth.tagsHash[i] <== tagsHasher[i].out;
		
		auth.pathTagsIndices[i] <== pathTagsIndices[i];
		for(var j = 0; j < cdl; j++) {
			auth.pathTags[i][j] <== pathTags[i][j];
		}

		gradesHasher[i] = CredentialLeafHasher();
		gradesHasher[i].property <== grades[i][0];
		gradesHasher[i].value <== grades[i][1];
		gradesHasher[i].salt <== grades[i][2];
		auth.gradesHash[i] <== gradesHasher[i].out;

		auth.pathGradesIndices[i] <== pathGradesIndices[i];
		for(var j = 0; j < cdl; j++) {
			auth.pathGrades[i][j] <== pathGrades[i][j];
		}
	}

	var sum = 0;
	for (var i = 0; i < n; i++) {
		sum += grades[i][1]*weights[i];
	}
	out <-- sum;
	out === result;
}
