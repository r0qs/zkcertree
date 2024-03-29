pragma circom 2.0.4;

include "commit.circom";
include "merkleProof.circom";

// Verifies that a commitment of a given secret and nullifier
// is included in the merkle tree of registered commitments.
// @param `levels` is the number of levels of the tree
template Approve(levels) {
	signal input root;
	signal input nullifierHash;
	signal input sender;

	signal input nullifier;
	signal input subject;
	signal input secret;
	signal input pathElements[levels];
	signal input pathIndices;

	// Verify commitment
	component hasher = CommitmentHasher();
	hasher.nullifier <== nullifier;
	hasher.subject <== subject;
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

	// Add hidden signals to make sure that tampering with sender will invalidate the snark proof
	// Squares are used to prevent optimizer from removing those constraints
	signal senderSquare;
	senderSquare <== sender * sender;
}
