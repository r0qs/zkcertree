pragma circom 2.0.4;

// Modified from: https://github.com/tornadocash/tornado-core/tree/master/circuits
include "../node_modules/circomlib/circuits/poseidon.circom";

// TODO: salt nullifier
// computes Poseidon(nullifier + subject + secret)
template CommitmentHasher() {
	signal input nullifier;
	signal input secret;
	signal input subject;
	signal output commitment;
	signal output nullifierHash;

	component commitmentHasher = Poseidon(3);
	commitmentHasher.inputs[0] <== nullifier;
	commitmentHasher.inputs[1] <== subject;
	commitmentHasher.inputs[2] <== secret;
	
	component nullifierHasher = Poseidon(1);
	nullifierHasher.inputs[0] <== nullifier;

	commitmentHasher.out ==> commitment;
	nullifierHasher.out ==> nullifierHash;
}

// computes Poseidon(pk.Ax + pk.Ay)
template Subject() {
	signal input publicKey[2];
	signal output out;

	component hasher = Poseidon(2);
	hasher.inputs[0] <== publicKey[0];
	hasher.inputs[1] <== publicKey[1];

	hasher.out ==> out;
}

// computes Poseidon(croot + salt)
template Nullifier() {
	signal input in;
	signal input salt;
	signal output out;

	component hasher = Poseidon(2);
	hasher.inputs[0] = in;
	hasher.inputs[1] = salt;

	hasher.out ==> out;
}

// computes Poseidon(key + value + salt)
template CredentialLeafHasher() {
	signal input key;
	signal input value;
	signal input salt;
	signal output out;

	component leaf = Poseidon(3);
	leaf.inputs[0] <== key;
	leaf.inputs[1] <== value;
	leaf.inputs[2] <== salt;

	leaf.out ==> out;
}
