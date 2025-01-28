// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Proxy} from "openzeppelin-contracts/contracts/proxy/Proxy.sol";
import {ERC1967Utils} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {Address} from "openzeppelin-contracts/contracts/utils/Address.sol";

/// @notice Proxy contract designed for EIP-7702 smart accounts.
///
/// @dev Implements ERC-1967, but with an initial implementation.
/// @dev Guards the initializer function, requiring a signed payload by the wallet to call it.
contract EIP7702Proxy is Proxy {
    // ERC1271 interface constants
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant ERC1271_ISVALIDSIGNATURE_SELECTOR = 0x1626ba7e;
    bytes4 internal constant ERC1271_FAIL_VALUE = 0xffffffff;

    address immutable proxy;
    address immutable initialImplementation;
    bytes4 immutable guardedInitializer;

    event Upgraded(address indexed implementation);

    error InvalidSignature();
    error InvalidInitializer();
    error InvalidImplementation();

    constructor(address implementation, bytes4 initializer) {
        proxy = address(this);
        initialImplementation = implementation;
        guardedInitializer = initializer;
    }

    function initialize(
        bytes calldata args,
        bytes calldata signature
    ) external {
        // construct hash incompatible with wallet RPCs to avoid phishing
        bytes32 hash = keccak256(abi.encode(proxy, args));
        address recovered = ECDSA.recover(hash, signature);
        if (recovered != address(this)) revert InvalidSignature();

        // enforce initialization only on initial implementation
        address implementation = _implementation();
        if (implementation != initialImplementation)
            revert InvalidImplementation();

        // Set the ERC-1967 implementation slot and emit Upgraded event
        ERC1967Utils.upgradeToAndCall(initialImplementation, "");

        Address.functionDelegateCall(
            initialImplementation,
            abi.encodePacked(guardedInitializer, args)
        );
    }

    function _implementation() internal view override returns (address) {
        address implementation = ERC1967Utils.getImplementation();
        return
            implementation != address(0)
                ? implementation
                : initialImplementation;
    }

    function _fallback() internal override {
        // block guarded initializer from being called
        if (msg.sig == guardedInitializer) revert InvalidInitializer();

        // Special handling for isValidSignature
        if (msg.sig == ERC1271_ISVALIDSIGNATURE_SELECTOR) {
            (bytes32 hash, bytes memory signature) = abi.decode(
                msg.data[4:],
                (bytes32, bytes)
            );

            // First try delegatecall to implementation
            (bool success, bytes memory result) = _implementation()
                .delegatecall(msg.data);

            // If delegatecall succeeded and returned magic value, return that
            if (
                success &&
                result.length == 32 &&
                abi.decode(result, (bytes4)) == ERC1271_MAGIC_VALUE
            ) {
                assembly {
                    mstore(0, ERC1271_MAGIC_VALUE)
                    return(0, 32)
                }
            }

            // Otherwise try ecrecover
            address recovered = ECDSA.recover(hash, signature);
            if (recovered == address(this)) {
                assembly {
                    mstore(0, ERC1271_MAGIC_VALUE)
                    return(0, 32)
                }
            }

            // If all checks fail, return failure value
            assembly {
                mstore(0, ERC1271_FAIL_VALUE)
                return(0, 32)
            }
        }

        _delegate(_implementation());
    }
}
