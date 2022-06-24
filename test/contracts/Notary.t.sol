// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "contracts/Notary.sol";
import "contracts/HasherFactory.sol";
import "contracts/Approve12Verifier.sol";

contract NotaryTest is Test {
    PrivateNotary public notary;
    address private owner = 0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1;
    uint32 private levels = 12;

    function setUp() public {
        bytes12 nonce = 0x000000000000000000000001;
        bytes32 salt = bytes32(abi.encodePacked(address(this), nonce));

        HasherFactory factory = new HasherFactory();
        address hasherContract = factory.deploy(salt);

        Approve12Verifier verifierContract = new Approve12Verifier();
        notary = new PrivateNotary(IVerifier(address(verifierContract)), levels, hasherContract, owner);

        bytes32 initialRoot = notary.getLastRoot();
        assert(initialRoot == 0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a);

        bytes32 commitment = 0x0d1f7acd1b0a075e79e0cab64efb42fad46c62aa6d18e24dfe570415ded12d86;
        vm.prank(owner);
        notary.issue(commitment);
    }

    function testApproval() public {
        bytes memory proof = hex"1efada5c7825d7074955126d2886abc99fb0c0f844d2d746bc141f285b44a19f05138302be1f9843037a37c706f5ec0bb07105148f634e61df811f74889d910803abb936a49aa0da4422eb268d3f707d20f6c48e8a8531433c190d17690222ce0e7672bf5020dcf584cb080bc4f767132a30316a6235cbf7dccc2bf5dc6351fe10e457217534c5eec046dd25f7cef9b45b93d589e8d73965ae59d4f9676d7f1801e4e87d28069a73c441af4c915ed64ce97380d1a3cc734542ee9e67c6b005ed2f6d53c81cfce12cf7f016b326d9eb6f255ad22733d45ffc649860a95fa4ea721f71983b58953dbb130d664ff19d8468ddc11c36d43760d179076d9dbd73aae52599c3b5e9e61ed1a477605c7281871598550fe6889914e81f58fcadd62f9740160cbfe694e54c6d75a00e9c7f1192a0b6081a180a1debab05052e5eadcedd32165ace63c7014eac493440e7a545dc0e734069d9631eee4c1e13c3eafd6ef2730d09e0fd14ad382b675d938e3637e298f16c817f078971a3c305bcad57c36f9a10263e8c7216ad05cfc17a676f1089523ce91552c7eb70e8265fa2ba728706220c2104f6b127fb6080fd8e16b7dc8f1c49ddede16c6474383162c4140bdfc2e614f7bc3fd4774b19d470956ccf96d0151b143d5f348de8a6b589a2d6c90948420e8b51fd498264010b162d70fe6c82f715aa9777f39e67292bf0f24db10c103b0ed4f43f82c9a472bfcf27de3940dbb2c6a69fb83d999e0d57c1a51bda5076201530525b7843789891e38529fe94f2d83b6fe4c47cc414b1e291581142384f991abe489b4b4fd0c7fc6fdce0d5d7bf1ce15d6e5390594eb1901d1fd5d2ca533e2c616e8b38c427e3b2c5ee00e56cd64fcb9723cd5683dda839a535e3e959fe571c7d0f06250cabac9a37b5dbd8b80438330a3eedb7bd5e8c94805c39b53a7f582090fdf4d1802fac720fb094955e72c406e2ba9510c62ba1726d18affef758140ba428f3e1a42b45675705fc39bd5eb3af5bad3ee0254662fa91a14e06a3fd9008e4c16d1f8388a81c8eec6c53a072628717c4290d36de41b7e177ce591700280be19918cc388e3395122877c2f05e63fb385f7633e4904db7789c2aff579872";

        bytes32 root = notary.getLastRoot(); // 0x17dac387178dba076f21e0131de6466b9a3aae27d8d645284dde9810d6715489
        bytes32 nullifier = 0x136cef32226a29779425c8644a50f627a7f2d8a1b8d9431a8340394a5e70d0bc;

        vm.prank(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);
        notary.approve(proof, root, nullifier);
    }
}
