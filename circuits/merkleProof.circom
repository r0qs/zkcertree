// The MerkleProof is taken from https://github.com/tornadocash/tornado-nova/tree/master/circuits
pragma circom 2.0.4;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/switcher.circom";

// Compute that merkle root for given the merkle proof and leaf.
// Note:
// - pathIndices bits is an array of 0/1 selectors telling whether given
// - pathElement is on the left or right side of merkle path.
template MerkleProof(levels) {
	signal input leaf;
	signal input pathElements[levels];
	signal input pathIndices;
	signal output root;

	component switcher[levels];
	component hasher[levels];

	component indexBits = Num2Bits(levels);
	indexBits.in <== pathIndices;

	for (var i = 0; i < levels; i++) {
		switcher[i] = Switcher();
		switcher[i].L <== i == 0 ? leaf : hasher[i - 1].out;
		switcher[i].R <== pathElements[i];
		switcher[i].sel <== indexBits.out[i];

		hasher[i] = Poseidon(2);
		hasher[i].inputs[0] <== switcher[i].outL;
		hasher[i].inputs[1] <== switcher[i].outR;
	}

	hasher[levels - 1].out ==> root;
}

// Helper function to check whether an elements is in the neighborhood array
function isKnownIndex(idx, neighborhood, n) {
	for (var i = 0; i < n; i++) {
		if (idx == neighborhood[i][0] || idx == neighborhood[i][1]) {
			return 1;
		}
	}
	return 0;
}

// Compute hashes of the next tree layer
// @param `height` is the layer height
template TreeLayer(height) {
	var nItems = 1 << height;
	signal input indices[nItems * 2];
	signal input proofElements[nItems * 2];
	signal input pathElements[nItems * 2];
	signal output nextIndices[nItems];
	signal output remainingPath[nItems];
	signal output layerElements[nItems];

	var neighborhood[nItems][4];
	var invalidPos = -1;
	assert(invalidPos == 21888242871839275222246405745257275088548364400416034343698204186575808495616);
	for(var i = 0; i < nItems; i++) {
		neighborhood[i][0] = invalidPos; // left node
		neighborhood[i][1] = invalidPos; // right node
		neighborhood[i][2] = 0; // left/right switch
		neighborhood[i][3] = 0; // proof/path switch
	}

	var c = 0;
	var z = 0;
	for(var k = 0; k < nItems; k++) {
		var elIdx = indices[z];
		if (elIdx != invalidPos && isKnownIndex(elIdx, neighborhood, nItems) == 0) {
			if (k == 0 || elIdx != 0 && k > 0) { // assumes sorted indices array
				neighborhood[c][0] = elIdx;
				if (indices[z + 1] == elIdx ^ 1) {
					neighborhood[c][1] = indices[z + 1];
					neighborhood[c][3] = 1;
					z += 2;
				} else {
					neighborhood[c][1] = elIdx ^ 1;
					z++;
				}
				if (elIdx % 2 != 0) {
					neighborhood[c][2] = 1;
				}
				c++;
			}
		}
	}

	var i = 0;
	var j = 0;
	var w = 0;
	var proof[nItems * 2];
	var remaining[nItems];
	for(var k = 0; k < nItems; k++) {
		if (i < z) {
			proof[k * 2] = proofElements[i];
			proof[k * 2 + 1] = (proofElements[i + 1] - pathElements[j])*neighborhood[k][3] + pathElements[j];
			if (neighborhood[k][3] == 1) {
				i += 2;
			} else {
				j++;
				i++;
			}
		} else {
			remaining[w] = pathElements[j];
			j++;
			w++;
		}
	}

	for(var k = 0; k < nItems; k++) {
		var nextIdx = (neighborhood[k][0] % 2 == 0) ? neighborhood[k][0] : neighborhood[k][1];
		nextIndices[k] <-- (nextIdx != invalidPos) ? nextIdx \ 2 : nextIdx;
		remainingPath[k] <-- remaining[k]; //FIXME: Non quadratic constraints
	}

	component switcher[nItems];
	var layer[nItems * 2];
	for(var k =0; k < nItems; k++) {
		switcher[k] = Switcher();
		switcher[k].sel <-- neighborhood[k][2];
		switcher[k].L <-- proof[k * 2];
		switcher[k].R <-- proof[k * 2 + 1];
		layer[k * 2] = switcher[k].outL;
		layer[k * 2 + 1] = switcher[k].outR;
	}

	component hash[nItems];
	for(var k = 0; k < nItems; k++) {
		hash[k] = Poseidon(2);
		hash[k].inputs[0] <== layer[k * 2];
		hash[k].inputs[1] <== layer[k * 2 + 1];
		hash[k].out ==> layerElements[k];
	}
}

// Compute that merkle root for given the merkle multiproof and leaves array.
// @param `levels` is the number of levels of the tree
template MerkleMultiProof(levels) {
	var nItems = 1 << levels;
	signal input leaves[nItems];
	signal input pathElements[nItems];
	signal input leafIndices[nItems]; 
	signal output root;

	component layers[levels];
	for(var level = levels - 1; level >= 0; level--) {
		layers[level] = TreeLayer(level);
		for(var i = 0; i < (1 << (level + 1)); i++) {
			layers[level].indices[i] <== level == levels - 1 ? leafIndices[i] : layers[level + 1].nextIndices[i];
			layers[level].proofElements[i] <== level == levels - 1 ? leaves[i] : layers[level + 1].layerElements[i];
			layers[level].pathElements[i] <== level == levels - 1 ? pathElements[i] : layers[level + 1].remainingPath[i];
		}
	}

	levels > 0 ? layers[0].layerElements[0] : leaves[0] ==> root;
}