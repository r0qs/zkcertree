// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "contracts/IssueVerifier.sol";

interface IVerifier {
    function verifyProof(bytes memory proof, uint256[] memory pubSignals) external view returns (bool);
}

contract IssuerVerifierTest is Test {
    IVerifier public verifier;
    bytes private proof;
    uint256[] private pubSignals;

    function setUp() public {
        IssueVerifier verifierContract = new IssueVerifier();
        verifier = IVerifier(address(verifierContract));
    }

    function testIssuanceProof() public {
        proof = hex"2b012eb251b41e77a3f4ca082e2519086264f4ef9a72515cabd397d2e11737ec1d1d7bea19ee294a70cb87eefdac548b92d4a85f1a31153b7401f5615f9e240308719dc903ad56ed9c54aa30c829ad4c41af47aabe0cc8447857900a5c35fad718630569e2e9534f7bb5f042484205c1554df50bbeeb961de743e05d325bffb01e113180adf94042d789f06970ad2d6408593c2ba0cd1ba0bcc2efa78c1c9abd1f8a82eaa6cfbd3ac2ba422d4307ab8055fff0dbb642d83972367ee53c8703510d7fcb4930c6f10f579870cd23c12e8f0a43ea6c3c5402d3f046f9c24ab8ec102ac7f86b0ce9e2136ad4d9f85887db38a485b013ade118884f37471969b13efc19272006e28c29d433533d1f2ab1e2e62a166729e28617c326061710e44cbfef03b4bfbb3cc493c445c923bdd38f71138369d8507772f30c6b0260fe6780f8ff2b53344e6a7bc54161dd654b9998bbb05b5975dfaa4ab3c1f7e72a637f1dfd252dc6ee2775392fb5119884adbf9178e6873cebe7b3c3470d8c993739d8a67c9629080699bcdd6e8203918fb286a9e03ac63bc912093865acc713fe177a13b01519159a893e4fdda2b9932fd169607e185ae2c507a27d0003c8d51a99014fff7018fba1f7b948a07e2cde1433d5185f24966ec79d430a0c6104ebfd3dedce70cd2460ea14c5b549fa36ace64338f076eaa65b9d928e26324242a0908745cdbd381adfa65d7e16e1e0842df8a340f3fdebfa028ba6e41edafb11aa3c11d95d66e106922706b0f4d6fee6e4f4e56dbaaa92ba3d7de4e332d16e9eb9a343a531563e25e86a15f9cfff01de3f5ef81fbba9543881822433dadf5cf5ae5e3bc9a7bb8e045e92b86f8ee7ccf5ce14ed534558720cf9a585d8cb47dbea406fdb2d4f2e860b21401fbe4705352c8c2184e1d8f12f29359b354a86e30f6cbfb80dccfe83760259071ba1fd129243defc460c76cf50e948ac8d883ccb460d1cd8df40fef2810b84612f2ef9b1111eb91c454fcaf0df8c4d7c8fe6bb3579211697eb4be7d1391b115d22d455f1afb42c2d7db4675698fffd9bb2e760ecb3018ab96aaf1dd5c0018065154e36a6bb17d4b15b0c6ae7f9228f360efe26cea360d8412b18a9b838";

        uint256[4] memory signals = [
            0x03e9d51c85c33ccbd944074457c2d78d1f97eb03e1bc894672da56dc7ff1481f,
            0x00000000000000000000000000000000000000000000000000019f250cf14908,
            0x2a80393e2c43f5117149af8b19cd1a375bbbe91f8125fe237c9b3e24377dc3c0,
            0x265cfde580258ce18f2a36e37f24c7d7a491055757095750c1640eebbea7f5c2
        ];

        for (uint256 i = 0; i < signals.length; i++) {
            pubSignals.push(signals[i]);
        }

        assertTrue(verifier.verifyProof(proof, pubSignals));
    }
}
