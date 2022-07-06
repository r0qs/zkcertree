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

        bytes32 commitment = 0x03e9d51c85c33ccbd944074457c2d78d1f97eb03e1bc894672da56dc7ff1481f;
        vm.prank(owner);
        notary.issue(commitment);
    }

    function testApproval() public {
        bytes memory proof = hex"02fade5f21f2b36f2d0a5e93ac9efa1a73017f901e6a35df07e747a91bbee9a0056b4ede79d92536adbf17e70f812ef0b5d2f3b52103e8e4daead2c0bf67b399137ac757ebbe7daec899e2dfee67957170d56a3a3f450aa5c7608208c0cec4e2026026b2edab1193262d0e59d3a4d68e63c5d20647db1f6e85ef95630d36c3210f6c0c78b9fcdbd9b618e8edaeb6164a3b6e6f0ee0265cc27a5b8376b1f774d51a1f421490afd0be8069b3afb84f491d68b29791a3092d98a886348ec7c3689b055983ff5152cf6acc164fa72be082e5e69a4fff4f130e3fa0e3b3627b6001dd1eb96783e113ae79fe25ab1a91831d549b3a84cfc51d43adaa1203437e2b0c0f24f69bcc046e011353bc78c6205565ccfe4fdf2cbc112c0bec2fbfaae78355400b3d52945bed1d163098f2fdc50efbdc1bd6fd5e1ce20baacc9678ab6d5522812c54015e1619edb02b0c3db239534834c31127ed9722f661807e6c614661798920084e8f369dc83b75cf24445f75cb016ef656c2d958639698bb32218eeb9ee8105f7a977244875744da881749247c2c406dc5aa6a9d12321aa7f0b00f20ecf22f66222ff443bb342bcc1b8fa0d9633ac94246d46feb0b7779bf53d4b3c43ba4181832c2801094a62e9c9ec05e367d7130bc6e808a7239171e39af967604e7f30d214ed247c42495506f136fe41fb889bf348fe0d2298bb037a6e58aa2ec4ed41b21ce976a992d23dee2432191e8442591fb77b471da0b44b9cf3c8a0b9628b519e566a128fa8586a46e7371c77f36998b457d12cb3acac75bbefe01977bd9dc24f447ce4784cc25b190863a7944283d4ce387f8c2725c1a065c83c13e4fa8460180d3f55fc0041ffc73287f4e532df73462743eab08f2499d61089996b1535b252890c4dc13be647d02e4c08636bf3f1cb9be9ceff745cf6321185702072f352185813a64b3a51de117d9b56affb97276d07a31fe81dc2e16bc2b8124e83fb814bbe5a8e64cfe3188f99da381f353337e736e64fab48b276d124169cb500a350d22445a28a501015d7528e11b1ae3be1e0544af11387b7cfa8d9072d1760dc40e2f0649baa96fba175da3eb2530847ba08434a1652171f58246cd80c6ead543";

        bytes32 root = notary.getLastRoot(); // 0x17faa6e7a75661ea2c28170e128b3e9871862d9dd6611a7593adabe5296fe695
        emit log_named_bytes32("last root", root);

        bytes32 nullifierHash = 0x23f060e722bc9a241766cf7f6fde13ad9910bd361c1e4948a8614bf1c1b0f806;
        address sender = 0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1;

        vm.prank(sender);
        notary.approve(proof, root, nullifierHash);
    }
}
