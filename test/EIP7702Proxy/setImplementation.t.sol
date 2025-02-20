// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EIP7702Proxy} from "../../src/EIP7702Proxy.sol";
import {NonceTracker} from "../../src/NonceTracker.sol";

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {ERC1967Utils} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {IERC1967} from "openzeppelin-contracts/contracts/interfaces/IERC1967.sol";

import {EIP7702ProxyBase} from "../base/EIP7702ProxyBase.sol";
import {MockImplementation} from "../mocks/MockImplementation.sol";

contract SetImplementationTest is EIP7702ProxyBase {
    MockImplementation newImplementation;
    bytes32 private constant _IMPLEMENTATION_RESET_TYPEHASH =
        keccak256(
            "EIP7702ProxyImplementationReset(uint256 chainId,address proxy,uint256 nonce,address currentImplementation,address newImplementation)"
        );

    function setUp() public override {
        super.setUp();
        newImplementation = new MockImplementation();
    }

    function _signResetData(
        uint256 signerPk,
        address newImplementationAddress,
        uint256 chainId
    ) internal view returns (bytes memory) {
        bytes32 resetHash = keccak256(
            abi.encode(
                _IMPLEMENTATION_RESET_TYPEHASH,
                chainId == 0 ? 0 : block.chainid,
                _proxy,
                _nonceTracker.nonces(_eoa),
                _getERC1967Implementation(_eoa),
                newImplementationAddress
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, resetHash);
        return abi.encodePacked(r, s, v);
    }

    function test_emitsUpgradedEvent() public {
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        vm.expectEmit(true, false, false, false, address(_eoa));
        emit IERC1967.Upgraded(address(newImplementation));

        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );
    }

    function test_succeeds_withChainIdZero() public {
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            0
        );

        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            true
        );

        assertEq(
            _getERC1967Implementation(_eoa),
            address(newImplementation),
            "Implementation should be set to new address"
        );
    }

    function test_succeeds_withNonzeroChainId() public {
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );
        assertEq(
            _getERC1967Implementation(_eoa),
            address(newImplementation),
            "Implementation should be set to new address"
        );
    }

    function test_reverts_whenChainIdMismatch(uint256 wrongChainId) public {
        vm.assume(wrongChainId != block.chainid);
        vm.assume(wrongChainId != 0);

        bytes32 resetHash = keccak256(
            abi.encode(
                _IMPLEMENTATION_RESET_TYPEHASH,
                wrongChainId,
                _proxy,
                _nonceTracker.nonces(_eoa),
                _getERC1967Implementation(_eoa),
                address(newImplementation)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_EOA_PRIVATE_KEY, resetHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );
    }

    function test_succeeds_whenImplementationSlotEmpty() public {
        vm.store(_eoa, ERC1967Utils.IMPLEMENTATION_SLOT, bytes32(0));

        assertEq(
            _getERC1967Implementation(address(_eoa)),
            address(0),
            "Implementation slot should be empty initially"
        );

        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );

        assertEq(
            _getERC1967Implementation(address(_eoa)),
            address(newImplementation),
            "Implementation should be set to new address"
        );
    }

    function test_succeeds_whenImplementationSlotHasForeignAddress(
        address foreignImpl
    ) public {
        MockImplementation foreignImplementation = new MockImplementation();

        vm.assume(foreignImpl != address(0));
        vm.assume(foreignImpl != address(_implementation));
        vm.assume(foreignImpl != address(newImplementation));
        assumeNotPrecompile(foreignImpl);

        vm.store(
            _eoa,
            ERC1967Utils.IMPLEMENTATION_SLOT,
            bytes32(uint256(uint160(address(foreignImplementation))))
        );

        assertEq(
            _getERC1967Implementation(_eoa),
            address(foreignImplementation),
            "Implementation slot should be set to foreign address"
        );

        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );

        assertEq(
            _getERC1967Implementation(_eoa),
            address(newImplementation),
            "Implementation should be set to new address"
        );
    }

    function test_succeeds_whenResettingToSameImplementation() public {
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );
        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );

        assertEq(
            _getERC1967Implementation(_eoa),
            address(newImplementation),
            "Implementation should be set to new address after first reset"
        );

        signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );

        assertEq(
            _getERC1967Implementation(_eoa),
            address(newImplementation),
            "Implementation should remain same address"
        );
    }

    function test_nonceIncrements_afterSuccessfulReset(uint8 numResets) public {
        vm.assume(numResets > 0 && numResets < 10);

        uint256 initialNonce = _nonceTracker.nonces(_eoa);

        for (uint8 i = 0; i < numResets; i++) {
            MockImplementation nextImplementation = new MockImplementation();

            bytes memory signature = _signResetData(
                _EOA_PRIVATE_KEY,
                address(nextImplementation),
                block.chainid
            );
            EIP7702Proxy(_eoa).setImplementation(
                address(nextImplementation),
                "",
                address(_validator),
                signature,
                false
            );

            assertEq(
                _nonceTracker.nonces(_eoa),
                initialNonce + i + 1,
                "Nonce should increment by one after each reset"
            );
        }
    }

    function test_reverts_whenSignatureEmpty() public {
        bytes memory signature = new bytes(0);

        vm.expectRevert(
            abi.encodeWithSignature("ECDSAInvalidSignatureLength(uint256)", 0)
        );
        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );
    }

    function test_reverts_whenSignatureLengthInvalid(uint8 length) public {
        vm.assume(length != 0);
        vm.assume(length != 65);

        bytes memory signature = new bytes(length);

        vm.expectRevert(
            abi.encodeWithSignature(
                "ECDSAInvalidSignatureLength(uint256)",
                length
            )
        );
        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );
    }

    function test_reverts_whenSignatureInvalid(
        bytes32 r,
        bytes32 s,
        uint8 v
    ) public {
        vm.assume(v != 27 && v != 28);

        bytes memory signature = abi.encodePacked(r, s, v);

        assertEq(signature.length, 65, "Signature should be 65 bytes");

        vm.expectRevert();
        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );
    }

    function test_reverts_whenSignerWrong(uint128 wrongPk) public {
        vm.assume(wrongPk != 0);
        vm.assume(wrongPk != _EOA_PRIVATE_KEY);

        bytes32 resetHash = keccak256(
            abi.encode(
                _IMPLEMENTATION_RESET_TYPEHASH,
                _eoa,
                address(newImplementation),
                _nonceTracker.nonces(_eoa)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, resetHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );
    }

    function test_resetImplementation_reverts_whenSignatureReplayedWithDifferentProxy(
        uint128 secondProxyPk
    ) public {
        vm.assume(secondProxyPk != 0);
        vm.assume(secondProxyPk != uint128(_EOA_PRIVATE_KEY));

        address payable secondProxy = payable(vm.addr(secondProxyPk));
        vm.assume(address(secondProxy) != address(_eoa));
        assumeNotPrecompile(address(secondProxy));

        bytes memory proxyCode = address(_proxy).code;
        vm.etch(secondProxy, proxyCode);
        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes32 _INITIALIZATION_TYPEHASH = keccak256(
            "EIP7702ProxyInitialization(uint256 chainId,address proxy,uint256 nonce,bytes args)"
        );
        bytes32 initHash = keccak256(
            abi.encode(
                _INITIALIZATION_TYPEHASH,
                0,
                _proxy,
                _nonceTracker.nonces(secondProxy),
                keccak256(initArgs)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(secondProxyPk, initHash);
        bytes memory initSignature = abi.encodePacked(r, s, v);
        EIP7702Proxy(secondProxy).setImplementation(
            address(newImplementation),
            initArgs,
            address(0),
            initSignature,
            true
        );

        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(secondProxy).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );
    }

    function test_reverts_whenSignatureReplayedWithDifferentImplementation(
        address differentImpl
    ) public {
        vm.assume(differentImpl != address(0));
        vm.assume(differentImpl != address(newImplementation));
        assumeNotPrecompile(differentImpl);

        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).setImplementation(
            differentImpl,
            "",
            address(_validator),
            signature,
            false
        );
    }

    function test_reverts_whenSignatureUsesWrongNonce(
        uint256 wrongNonce
    ) public {
        uint256 currentNonce = _nonceTracker.nonces(_eoa);

        vm.assume(wrongNonce != currentNonce);

        bytes32 resetHash = keccak256(
            abi.encode(
                _IMPLEMENTATION_RESET_TYPEHASH,
                _proxy,
                address(newImplementation),
                wrongNonce
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_EOA_PRIVATE_KEY, resetHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );
    }

    function test_reverts_whenSignatureReplayedWithSameNonce() public {
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );
        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );

        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );
    }

    function test_reverts_whenSignatureUsesWrongCurrentImplementation() public {
        MockImplementation wrongCurrentImpl = new MockImplementation();

        uint256 expectedNonce = _nonceTracker.nonces(_eoa);

        bytes32 resetHash = keccak256(
            abi.encode(
                _IMPLEMENTATION_RESET_TYPEHASH,
                _proxy,
                address(wrongCurrentImpl),
                address(newImplementation),
                block.chainid,
                expectedNonce
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_EOA_PRIVATE_KEY, resetHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).setImplementation(
            address(newImplementation),
            "",
            address(_validator),
            signature,
            false
        );
    }
}
