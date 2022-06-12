pragma circom 2.0.4;

// Modified from: https://github.com/tornadocash/tornado-core/tree/master/circuits
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

// computes Poseidon(nullifier + secret)
template CommitmentHasher() {
	signal input nullifier;
	signal input secret;
	signal output commitment;
	signal output nullifierHash;

	component commitmentHasher = Poseidon(2);
	commitmentHasher.inputs[0] <== nullifier;
	commitmentHasher.inputs[1] <== secret;
	
	component nullifierHasher = Poseidon(1);
	nullifierHasher.inputs[0] <== nullifier;

	commitmentHasher.out ==> commitment;
	nullifierHasher.out ==> nullifierHash;
}

// computes Poseidon(salt + private key)
template SecretHasher() {
	signal input salt;
	signal input prvKey;
	signal output secretHash;

	component poseidon = Poseidon(2);
	poseidon.inputs[0] <== salt;
	poseidon.inputs[1] <== prvKey;

	poseidon.out ==> secretHash;
}