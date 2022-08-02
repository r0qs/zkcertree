pragma circom 2.0.4;

// @param `n` is the number of elements.
// Must be the same for both inputs.
template DotProduct(n) {
	signal input a[n];
	signal input b[n];
	signal output out;

	signal temp[n];
	var sum = 0;
	for (var i = 0; i < n; i++) {
		temp[i] <== a[i]*b[i];
		sum += temp[i];
	}
	sum ==> out;
}