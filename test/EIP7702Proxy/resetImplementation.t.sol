// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EIP7702Proxy} from "../../src/EIP7702Proxy.sol";
import {NonceTracker} from "../../src/NonceTracker.sol";

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {ERC1967Utils} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {IERC1967} from "openzeppelin-contracts/contracts/interfaces/IERC1967.sol";

import {EIP7702ProxyBase} from "../base/EIP7702ProxyBase.sol";
import {MockImplementation} from "../mocks/MockImplementation.sol";

contract ResetImplementationTest is EIP7702ProxyBase {
    MockImplementation newImplementation;
    bytes32 private constant RESET_IMPLEMENTATION_TYPEHASH =
        keccak256(
            "EIP7702ProxyImplementationReset(address proxy,address currentImplementation,address newImplementation,uint256 chainId,uint256 nonce)"
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
                RESET_IMPLEMENTATION_TYPEHASH,
                _proxy,
                _getERC1967Implementation(_eoa),
                newImplementationAddress,
                chainId == 0 ? 0 : block.chainid,
                _nonceTracker.getNextNonce(_eoa)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, resetHash);
        return abi.encodePacked(r, s, v);
    }

    function test_emitsUpgradedEvent() public {
        // Get signature for reset
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        // Expect the Upgraded event
        vm.expectEmit(true, false, false, false, address(_eoa));
        emit IERC1967.Upgraded(address(newImplementation));

        // Reset implementation
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );
    }

    function test_succeeds_withChainIdZero() public {
        // Get signature for reset with chainId 0 (cross-chain)
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            0 // Cross-chain signature
        );

        // Reset implementation
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            0
        );
    }

    function test_reverts_whenChainIdMismatch(uint256 wrongChainId) public {
        vm.assume(wrongChainId != block.chainid);
        vm.assume(wrongChainId != 0);

        // Get signature for reset with current chain ID
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        // Try to use with wrong chain ID
        vm.expectRevert(EIP7702Proxy.InvalidChainId.selector);
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            wrongChainId
        );
    }

    function test_succeeds_whenImplementationSlotEmpty() public {
        // Clear the implementation slot
        vm.store(_eoa, ERC1967Utils.IMPLEMENTATION_SLOT, bytes32(0));

        // Verify slot is empty
        assertEq(
            _getERC1967Implementation(address(_eoa)),
            address(0),
            "Implementation slot should be empty initially"
        );

        // Get signature for reset
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        // Reset implementation
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );

        // Verify implementation was set
        assertEq(
            _getERC1967Implementation(address(_eoa)),
            address(newImplementation),
            "Implementation should be set to new address"
        );
    }

    function test_succeeds_whenImplementationSlotHasForeignAddress(
        address foreignImpl
    ) public {
        // Deploy another implementation to use as foreign implementation
        MockImplementation foreignImplementation = new MockImplementation();

        vm.assume(foreignImpl != address(0));
        vm.assume(foreignImpl != address(_implementation));
        vm.assume(foreignImpl != address(newImplementation));
        assumeNotPrecompile(foreignImpl);

        // Set implementation slot to foreign implementation
        vm.store(
            _eoa,
            ERC1967Utils.IMPLEMENTATION_SLOT,
            bytes32(uint256(uint160(address(foreignImplementation))))
        );

        // Verify slot was set
        assertEq(
            _getERC1967Implementation(_eoa),
            address(foreignImplementation),
            "Implementation slot should be set to foreign address"
        );

        // Get signature for reset
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        // Reset implementation
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );

        // Verify implementation was changed
        assertEq(
            _getERC1967Implementation(_eoa),
            address(newImplementation),
            "Implementation should be set to new address"
        );
    }

    function test_succeeds_whenResettingToSameImplementation() public {
        // First set implementation to newImplementation
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );

        // Verify first reset was successful
        assertEq(
            _getERC1967Implementation(_eoa),
            address(newImplementation),
            "Implementation should be set to new address after first reset"
        );

        // Get new signature for resetting to same implementation
        signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        // Reset to same implementation
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );

        // Verify implementation remains unchanged
        assertEq(
            _getERC1967Implementation(_eoa),
            address(newImplementation),
            "Implementation should remain same address"
        );
    }

    function test_nonceIncrements_afterSuccessfulReset(uint8 numResets) public {
        // Limit number of resets to avoid excessive gas usage
        vm.assume(numResets > 0 && numResets < 10);

        uint256 initialNonce = _nonceTracker.getNextNonce(_eoa);

        for (uint8 i = 0; i < numResets; i++) {
            // Deploy a new implementation for each reset
            MockImplementation nextImplementation = new MockImplementation();

            // Perform reset
            bytes memory signature = _signResetData(
                _EOA_PRIVATE_KEY,
                address(nextImplementation),
                block.chainid
            );
            EIP7702Proxy(_eoa).resetImplementation(
                address(nextImplementation),
                signature,
                block.chainid
            );

            // Verify nonce incremented correctly
            assertEq(
                _nonceTracker.getNextNonce(_eoa),
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
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );
    }

    function test_reverts_whenSignatureLengthInvalid(uint8 length) public {
        // ECDSA signatures must be 65 bytes
        // Exclude 0 (tested separately) and 65 (valid length)
        vm.assume(length != 0);
        vm.assume(length != 65);

        // Create signature of invalid length
        bytes memory signature = new bytes(length);

        vm.expectRevert(
            abi.encodeWithSignature(
                "ECDSAInvalidSignatureLength(uint256)",
                length
            )
        );
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );
    }

    function test_reverts_whenSignatureInvalid(
        bytes32 r,
        bytes32 s,
        uint8 v
    ) public {
        // Create 65-byte signature from random components
        // Exclude v = 27 or 28 as those are valid v values in ECDSA
        vm.assume(v != 27 && v != 28);

        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify signature is correct length
        assertEq(signature.length, 65, "Signature should be 65 bytes");

        // Any of these errors could occur for invalid signatures
        vm.expectRevert(); // Just check that it reverts, don't check specific error
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );
    }

    function test_reverts_whenSignerWrong(uint128 wrongPk) public {
        vm.assume(wrongPk != 0);
        vm.assume(wrongPk != _EOA_PRIVATE_KEY); // Not the valid signer

        bytes32 resetHash = keccak256(
            abi.encode(
                RESET_IMPLEMENTATION_TYPEHASH,
                _eoa,
                address(newImplementation),
                _nonceTracker.getNextNonce(_eoa)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, resetHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );
    }

    function test_resetImplementation_reverts_whenSignatureReplayedWithDifferentProxy(
        uint128 secondProxyPk
    ) public {
        vm.assume(secondProxyPk != 0);
        vm.assume(secondProxyPk != uint128(_EOA_PRIVATE_KEY));

        // Derive the second EOA/proxy address from the private key
        address payable secondProxy = payable(vm.addr(secondProxyPk));
        vm.assume(address(secondProxy) != address(_eoa));
        assumeNotPrecompile(address(secondProxy));

        // Deploy and initialize second proxy
        bytes memory proxyCode = address(_proxy).code;
        vm.etch(secondProxy, proxyCode);
        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes32 INIT_TYPEHASH = keccak256(
            "EIP7702ProxyInitialization(address proxy,bytes32 args,uint256 nonce)"
        );
        bytes32 initHash = keccak256(
            abi.encode(
                INIT_TYPEHASH,
                _proxy,
                keccak256(initArgs),
                _nonceTracker.getNextNonce(secondProxy) // can't use util signature function because we need to use the second proxy's nonce
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(secondProxyPk, initHash);
        bytes memory initSignature = abi.encodePacked(r, s, v);
        EIP7702Proxy(secondProxy).initialize(initArgs, initSignature);

        // Get signature for first proxy
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        // Try to use same signature with different proxy
        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(secondProxy).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );
    }

    function test_reverts_whenSignatureReplayedWithDifferentImplementation(
        address differentImpl
    ) public {
        vm.assume(differentImpl != address(0));
        vm.assume(differentImpl != address(newImplementation));
        assumeNotPrecompile(differentImpl);

        // Get signature for first implementation
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );

        // Try to use same signature with different implementation
        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).resetImplementation(
            differentImpl,
            signature,
            block.chainid
        );
    }

    function test_reverts_whenSignatureUsesWrongNonce(
        uint256 wrongNonce
    ) public {
        // Get current nonce
        uint256 currentNonce = _nonceTracker.getNextNonce(_eoa);

        // Exclude the current valid nonce
        vm.assume(wrongNonce != currentNonce);

        // Create signature with wrong nonce
        bytes32 resetHash = keccak256(
            abi.encode(
                RESET_IMPLEMENTATION_TYPEHASH,
                _proxy,
                address(newImplementation),
                wrongNonce
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_EOA_PRIVATE_KEY, resetHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );
    }

    function test_reverts_whenSignatureReplayedWithSameNonce() public {
        // First reset
        bytes memory signature = _signResetData(
            _EOA_PRIVATE_KEY,
            address(newImplementation),
            block.chainid
        );
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );

        // Try to replay the same signature
        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );
    }

    function test_reverts_whenSignatureUsesWrongCurrentImplementation() public {
        // Deploy a different implementation to use as "wrong" current implementation
        MockImplementation wrongCurrentImpl = new MockImplementation();

        // Get expected nonce
        uint256 expectedNonce = _nonceTracker.getNextNonce(_eoa);

        // Create signature with wrong current implementation
        bytes32 resetHash = keccak256(
            abi.encode(
                RESET_IMPLEMENTATION_TYPEHASH,
                _proxy,
                address(wrongCurrentImpl), // Use wrong implementation in signature
                address(newImplementation),
                block.chainid,
                expectedNonce
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_EOA_PRIVATE_KEY, resetHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Try to use signature with wrong current implementation
        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).resetImplementation(
            address(newImplementation),
            signature,
            block.chainid
        );
    }
}
