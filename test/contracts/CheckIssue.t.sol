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
        proof = hex"1fe0de0a315f0f2c9c2eb880cfd2772ae32765eb409ad78bde5dcdd6735821492b702b5f3b3940422ff4f287c061e05dcf8aadb7f5d25017e89a78385c197558241753769298bbfdea290304d598122c14f902af6d5e23afeb995504cbfde95e288d3ec95f79ea6ae6b5f5aaf35c4cc90618481a0a66b621c7728964253d630010b58084e01a05b1d8ac54e8958a977f497762882a29a415f8081cf22f6b7cc603c168272a125f2877541f66eaa08f2438b04c9891405e91f33479653a4faf320b03fe765a41cd08b1405a97dc7e9cdfbced3d24a4cc706a4c3530d2d4f171ef27157dbb5363c0886a56292672dacefcf99ad5f82a86432c727c36ee6133dea207472d846fa3f70f626990e050d4190ab5e2af499beb71a299215476a769d062151bb5d89aed4f467c4226caa9030586bdc98a232a1477b35f2d85fe327e6fc31135d1bacba19c015205a84d2efbc16bfe8fc6dfd3db974165947044a7ded2f601baf5739b331b73c75147ea879f5e5df73495214578d124581bf9252727d99e1e7f3ce679c3ddbfa891139bc702ec728b59e6fd5c43da2b1bc4e48211f8cd24239822d5ebb308cf0962c7138c3b8335d64cd17b7819a5d74c88ae016f07be6d0536f606f91917ea7283c9345b4d14041f63d5d5e8d35cfc9e91b37e6c1c6d8c12ed1431f96d71bbfcc67110b450e7214decf51ea8332c36900bac8e4becd1bc12768090bebb84b62f55f917ead732597dff4d5fc0157811e183a85b6bc3048c0d7693bb9b54a7a486d11178c256b698a961b90bef34cdadaaf6bf00dfb5404f2949301d7dd9efe03980d75865b4cb75d20f597ad3134104c97e069c54df126e0e147f51667a58515fe708e26dfc3ed46c693d114ad007666f8014dfa24834190b7a0b67ed7840e3e1fe38ad9dcc9cd6aefd438cbe1b283abb0223db3645e03e1ae89f34e5f83bf0301dd485c298f081a01e60c1555c1708a0ff10ce5a026865144678ce765e9313351c811d3260485a1b914df3362958bd85961b39bbade7660d91792c024bc4d2a1c7ae5641d7dfd9cb9c07c0a76388ea7ee37b6fd20297920168f37be1fddb329445161baf86e2331cc624db3e27d0116319ea4e5a690e4f";

        uint256[4] memory signals = [
            0x1c8b7c19af319b79b2304c31a0418803da51a3ec4d59499afe28fb90bfde15ed,
            0x15824e4f46cd754d1f989870458d07caf2c20d94cf4510eaecbd37d1667ffb9c,
            0x2a80393e2c43f5117149af8b19cd1a375bbbe91f8125fe237c9b3e24377dc3c0,
            0x265cfde580258ce18f2a36e37f24c7d7a491055757095750c1640eebbea7f5c2
        ];

        for (uint256 i = 0; i < signals.length; i++) {
            pubSignals.push(signals[i]);
        }

        assertTrue(verifier.verifyProof(proof, pubSignals));
    }
}
