pragma circom 2.0.4;

include "commit.circom";
include "merkleProof.circom";

// Verifies that a commitment of a given secret and nullifier
// is included in the merkle tree of registered commitments.
template Approve(levels) {
	signal input root;
	signal input nullifierHash;
	signal input subject;

	signal input nullifier;
	signal input secret;
	signal input pathElements[levels];
	signal input pathIndices;

	// Verify commitment
	component hasher = CommitmentHasher();
	hasher.nullifier <== nullifier;
	hasher.secret <== secret;
	hasher.nullifierHash === nullifierHash;

	// Verify inclusion proof
	component tree = MerkleProof(levels);
	tree.leaf <== hasher.commitment;
	tree.pathIndices <== pathIndices;
	for (var i = 0; i < levels; i++) {
		tree.pathElements[i] <== pathElements[i];
	}
	tree.root === root;

	// Add hidden signals to make sure that tampering with subject will invalidate the snark proof
	// Squares are used to prevent optimizer from removing those constraints
	signal subjectSquare;
	subjectSquare <== subject * subject;
}
