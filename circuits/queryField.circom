pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/mux3.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "presentationFieldsAuth.circom";

// Compare compares a with b based on the given operator op
// Operator is represented as a 3 bits bitmap.
// Currently supported operations are:
// 000: ==
// 001: !=
// 010: >
// 011: >=
// 100: <
// 101: <=
// 110: not_implemented
// 111: not_implemented
// It returns out with 1 if the condition is satisfied or 0 otherwise.
template Compare() {
	signal input a;
	signal input b;
	signal input op;
	signal output out;

	component validOp = LessThan(252);
	validOp.in[0] <== op;
	validOp.in[1] <== 6;
	// Restrict to supported operators
	assert(validOp.out);

	component eq = IsEqual();
	eq.in[0] <== a;
	eq.in[1] <== b;

	component gt = GreaterThan(252);
	gt.in[0] <== a;
	gt.in[1] <== b;
	
	component gte = GreaterEqThan(252);
	gte.in[0] <== a;
	gte.in[1] <== b;

	component lt = LessThan(252);
	lt.in[0] <== a;
	lt.in[1] <== b;

	component lte = LessEqThan(252);
	lte.in[0] <== a;
	lte.in[1] <== b;

	component mux = Mux3();
	component n2b = Num2Bits(3);
	n2b.in <== op;
	mux.s[0] <== n2b.out[0];
	mux.s[1] <== n2b.out[1];
	mux.s[2] <== n2b.out[2];

	mux.c[0] <== eq.out;
	mux.c[1] <== 1 - eq.out;
	mux.c[2] <== gt.out;
	mux.c[3] <== gte.out;
	mux.c[4] <== lt.out;
	mux.c[5] <== lte.out;
	mux.c[6] <== 0;
	mux.c[7] <== 0;

	mux.out ==> out;
}

// Verifies whether a field in a credential met a conditional criteria
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

// Verifies whether a field in all credentials met a conditional criteria
template VerifyConditionalQueryCredentials(n, cdl, ctl) {
	signal input certreeRoot;
	signal input fieldKey;
	signal input criterion;
	signal input operator;

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
