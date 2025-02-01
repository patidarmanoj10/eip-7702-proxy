// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {EIP7702ProxyBase} from "../base/EIP7702ProxyBase.sol";
import {EIP7702Proxy} from "../../src/EIP7702Proxy.sol";
import {MockImplementation, RevertingInitializerMockImplementation} from "../mocks/MockImplementation.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

contract InitializeTest is EIP7702ProxyBase {
    function test_succeeds_withValidSignatureAndArgs(address newOwner) public {
        vm.assume(newOwner != address(0));
        assumeNotPrecompile(newOwner);

        bytes memory initArgs = _createInitArgs(newOwner);
        bytes memory signature = _signInitData(_EOA_PRIVATE_KEY, initArgs);

        EIP7702Proxy(_eoa).initialize(initArgs, signature);

        // Verify owner was set correctly
        assertTrue(
            MockImplementation(payable(_eoa)).owner() == newOwner,
            "Owner should be set to fuzzed address"
        );
    }

    function test_setsERC1967ImplementationSlot(address newOwner) public {
        vm.assume(newOwner != address(0));
        assumeNotPrecompile(newOwner);

        bytes memory initArgs = _createInitArgs(newOwner);
        bytes memory signature = _signInitData(_EOA_PRIVATE_KEY, initArgs);

        EIP7702Proxy(_eoa).initialize(initArgs, signature);

        address storedImpl = _getERC1967Implementation(address(_eoa));
        assertEq(
            storedImpl,
            address(_implementation),
            "ERC1967 implementation slot should store implementation address"
        );
    }

    function test_emitsUpgradedEvent() public {
        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes memory signature = _signInitData(_EOA_PRIVATE_KEY, initArgs);

        vm.expectEmit(true, false, false, false, address(_eoa));
        emit EIP7702Proxy.Upgraded(address(_implementation));
        EIP7702Proxy(_eoa).initialize(initArgs, signature);
    }

    function test_reverts_whenSignatureLengthInvalid(address newOwner) public {
        bytes memory initArgs = _createInitArgs(newOwner);
        bytes memory signature = hex"deadbeef"; // Too short to be valid ECDSA signature

        vm.expectRevert(
            abi.encodeWithSignature("ECDSAInvalidSignatureLength(uint256)", 4)
        );
        EIP7702Proxy(_eoa).initialize(initArgs, signature);
    }

    function test_reverts_whenSignatureInvalid(address newOwner) public {
        bytes memory initArgs = _createInitArgs(newOwner);
        // 65 bytes of invalid signature data
        bytes memory signature = new bytes(65);

        vm.expectRevert(abi.encodeWithSignature("ECDSAInvalidSignature()"));
        EIP7702Proxy(_eoa).initialize(initArgs, signature);
    }

    function test_reverts_whenSignerWrong(uint128 wrongPk) public {
        vm.assume(wrongPk != 0);
        vm.assume(wrongPk != _EOA_PRIVATE_KEY); // Not the valid signer

        bytes memory initArgs = _createInitArgs(_newOwner);
        bytes32 initHash = keccak256(abi.encode(_eoa, initArgs));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPk, initHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).initialize(initArgs, signature);
    }

    function test_reverts_whenDelegatecallFails(address newOwner) public {
        vm.assume(newOwner != address(0));
        assumeNotPrecompile(newOwner);

        // Deploy reverting implementation
        _implementation = new RevertingInitializerMockImplementation();
        _initSelector = RevertingInitializerMockImplementation
            .initialize
            .selector;

        // Deploy proxy normally first to get the correct immutable values
        _proxy = new EIP7702Proxy(address(_implementation), _initSelector);

        // Get the proxy's runtime code
        bytes memory proxyCode = address(_proxy).code;

        // Etch the proxy code at the EOA's address
        vm.etch(_eoa, proxyCode);

        // Try to initialize with valid signature but reverting implementation
        bytes memory initArgs = _createInitArgs(newOwner);
        bytes memory signature = _signInitData(_EOA_PRIVATE_KEY, initArgs);

        vm.expectRevert("InitializerReverted");
        EIP7702Proxy(_eoa).initialize(initArgs, signature);
    }

    function test_reverts_whenSignatureReplayedWithDifferentProxy(
        address payable secondProxy,
        address newOwner
    ) public {
        vm.assume(address(secondProxy) != address(0));
        vm.assume(address(secondProxy) != address(_eoa));
        assumeNotPrecompile(address(secondProxy));
        assumeNotPrecompile(newOwner);

        // Get signature for first proxy
        bytes memory initArgs = _createInitArgs(newOwner);
        bytes memory signature = _signInitData(_EOA_PRIVATE_KEY, initArgs);

        // Deploy a second proxy with same implementation
        _deployProxy(secondProxy);

        // Try to use same signature with different proxy
        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(secondProxy).initialize(initArgs, signature);
    }

    function test_reverts_whenSignatureReplayedWithDifferentArgs(
        address differentOwner,
        address newOwner
    ) public {
        vm.assume(differentOwner != address(0));
        vm.assume(differentOwner != newOwner);
        assumeNotPrecompile(differentOwner);
        assumeNotPrecompile(newOwner);

        // Get signature for first initialization args
        bytes memory initArgs = _createInitArgs(newOwner);
        bytes memory signature = _signInitData(_EOA_PRIVATE_KEY, initArgs);

        // Try to use same signature with different args
        bytes memory differentArgs = _createInitArgs(differentOwner);
        vm.expectRevert(EIP7702Proxy.InvalidSignature.selector);
        EIP7702Proxy(_eoa).initialize(differentArgs, signature);
    }

    function test_constructor_reverts_whenImplementationZero() public {
        vm.expectRevert(EIP7702Proxy.ZeroValueConstructorArguments.selector);
        new EIP7702Proxy(address(0), MockImplementation.initialize.selector);
    }

    function test_constructor_reverts_whenInitializerZero() public {
        vm.expectRevert(EIP7702Proxy.ZeroValueConstructorArguments.selector);
        new EIP7702Proxy(address(_implementation), bytes4(0));
    }
}
