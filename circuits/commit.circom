pragma circom 2.0.4;

// Modified from: https://github.com/tornadocash/tornado-core/tree/master/circuits
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

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

// computes Poseidon(property_hash + value + salt)
template CredentialLeafHasher() {
	signal input property;
	signal input value;
	signal input salt;
	signal output out;

	component leaf = Poseidon(3);
	leaf.inputs[0] <== property;
	leaf.inputs[1] <== value;
	leaf.inputs[2] <== salt;

	leaf.out ==> out;
}
