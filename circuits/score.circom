pragma circom 2.0.4;

include "auth.circom";

template Score(n, ctl, cdl) {
	signal input roots[n];
	signal input nullifierHashes[n];
	signal input tags[n];
	signal input weights[n];
	signal input result;

	signal input subjects[n];
	signal input nullifiers[n];
	signal input secrets[n];
	signal input pathCertreeElements[n][ctl];
	signal input pathCertreeIndices[n];
	signal input grades[n];
	signal input pathGrades[n][cdl];
	signal input pathGradesIndices[n];
	signal input pathTags[n][cdl];
	signal input pathTagsIndices[n];

	signal output out;

	component auth = OffchainAuthCommitments(n, ctl, cdl);
	for(var i = 0; i < n; i++) {
		auth.roots[i] <== roots[i];
		auth.nullifierHashes[i] <== nullifierHashes[i];
		auth.subjects[i] <== subjects[i];
		auth.nullifiers[i] <== nullifiers[i];
		auth.secrets[i] <== secrets[i];
		auth.pathCertreeIndices[i] <== pathCertreeIndices[i];
		for(var j = 0; j < ctl; j++) {
			auth.pathCertreeElements[i][j] <== pathCertreeElements[i][j];
		}
		
		auth.grades[i] <== grades[i];
		auth.pathGradesIndices[i] <== pathGradesIndices[i];
		for(var j = 0; j < cdl; j++) {
			auth.pathGrades[i][j] <== pathGrades[i][j];
		}

		auth.tags[i] <== tags[i];
		auth.pathTagsIndices[i] <== pathTagsIndices[i];
		for(var j = 0; j < cdl; j++) {
			auth.pathTags[i][j] <== pathTags[i][j];
		}
	}

	var sum = 0;
	for (var i = 0; i < n; i++) {
		sum += grades[i]*weights[i];
	}
	out <-- sum;
	out === result;
}
