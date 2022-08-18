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
        assert(initialRoot == 0x0427a96ac2c931988962edf8cac479e84c4d662b324c004b1b13013069074085);

        bytes32 commitment = 0x03e9d51c85c33ccbd944074457c2d78d1f97eb03e1bc894672da56dc7ff1481f;
        vm.prank(owner);
        notary.issue(commitment);
    }

    function testApproval() public {
        bytes memory proof = hex"0b00efdd4dd0137665ef3a58670c6973dcea78f323875d8e468e4891250ac01c106077c0365ec3f5ad7cdf0b333013f3fc0eb40b866147f6f545ca513d31e49e25dd8b2a53129edd5c22e9c4d593db98052cee32660bf92235f4826b511e3f1829c41dc5d866b7a13b5a8a6a0e98d63a6594e88b1802fa6654f3ac896810ca180669e362c4611a36576e9f6869ffc2abcdf7a78f9cf738bac9d77ffee03cc3680cd40b951cb453a99e5880e8c1c8a3ed3dfb7457ff5457e400b11ab16cc2fbec04dff51a8a9114fb412ff793e4cfe2a02b5a8d4a71f67fc415912d61dddbcd072bfe02be9dc2d0bad6111020b49d6807336249b749d083e6db1b25662ec66e090ac38e7a449c81554636644c7d300f78ab61e390de3893ed2af500d8c7a7969012fbd8361035ebef93810675f97ffdac9784b2b08d7b8595b32f8668efef11c901f2badc339921255ce210ae0a93f0197ac53d4b97b1fb8905a73f95dc71efec0abc9a20ba07837a591c926dd95a727c170e8b085aad16162eec3581cc66066004bb5cbb6b02b058a3907339931d83cc9e0a5e2aebeb08ea3b5d160f73f7b71f0bb0f1e12440f4b4dbeb5ca01b2d8c5e62b0852865f2f6123ab2e41a286e7afa24926a04ee58ac7898c6302ba9971e980869a713d0ef96f40c2fc5a372fdeb39195ec5af67ecc7c03239f71d94376ddfecfd84dcdd43ad404dcb52fe97a0be7a0984d3fee7feb10b779e020100e356d3838c730b013a0e6101913cb91379291212c9e36c9d5e455a72c7cac3754fbbacbc41e108cc592b79de19d7468acb02fd17f69872bcba131896503dc22f322fe6e7068947dfe4a8a17034754331c9c0b6104dd4808711856070de2604720dad7d5d27cda074253e94b7d1b054ec9f57f8213723d83a1cd303b062d551260371cdfbe87a76166bf2fcdc2a11e5e17a4a752ff8f86323538cc7df9a0209038045e8d0b63e684801fd448ac62a9f90beeb9d05daa1c0605520adc393142edb573bd0341c2942ed02446afe778581a17aefd31314e6f35db21102ad2176fb353747679b2188218ac2d33ed89d68978a4cb6b80f98d0bde5c3377469450242d4c39952c24baced9df249f5ea8c1e1912bc7935";

        bytes32 root = notary.getLastRoot();
        assert(root == 0x12a77d9cdbe74c5acf88881b9eb373000f80be4531a0f6e600a03df8ac5d0f28);

        bytes32 nullifierHash = 0x23f060e722bc9a241766cf7f6fde13ad9910bd361c1e4948a8614bf1c1b0f806;
        address sender = 0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1;

        vm.prank(sender);
        notary.approve(proof, root, nullifierHash);
    }
}
