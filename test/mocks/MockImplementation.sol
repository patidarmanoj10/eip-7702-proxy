// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";
import {MultiOwnable} from "../../lib/smart-wallet/src/MultiOwnable.sol";

/**
 * @title MockImplementation
 * @dev Base mock implementation for testing EIP7702Proxy
 */
contract MockImplementation is UUPSUpgradeable, MultiOwnable {
    bytes4 constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    address public owner;
    bool public initialized;
    bool public mockFunctionCalled;

    event Initialized(address owner);
    event MockFunctionCalled();

    error AlreadyInitialized();
    error MockRevert();

    /// @dev Modifier to restrict access to owner
    modifier onlyOwner() override {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    /// @dev Modifier to prevent multiple initializations
    modifier initializer() {
        if (initialized) revert AlreadyInitialized();
        initialized = true;
        _;
    }

    /**
     * @dev Initializes the contract with an owner
     * @param owners Addresses to set as owners
     */
    function initialize(bytes[] calldata owners) external {
        _initializeOwners(owners);
        emit Initialized(address(uint160(uint256(bytes32(owners[0])))));
    }

    /**
     * @dev Mock function for testing delegate calls
     */
    function mockFunction() external {
        if (msg.sender != owner) {
            revert Unauthorized();
        }
        mockFunctionCalled = true;
        emit MockFunctionCalled();
    }

    function isValidSignature(
        bytes32,
        bytes calldata
    ) external pure virtual returns (bytes4) {
        return ERC1271_MAGIC_VALUE;
    }

    /**
     * @dev Implementation of UUPS upgrade authorization
     */
    function _authorizeUpgrade(
        address
    ) internal view virtual override onlyOwner {}

    /**
     * @dev Mock function that returns arbitrary bytes data
     * @param data The data to return
     * @return The input data (to verify delegation preserves data)
     */
    function returnBytesData(
        bytes memory data
    ) public pure returns (bytes memory) {
        return data;
    }

    /**
     * @dev Mock function that always reverts
     */
    function revertingFunction() public pure {
        revert("MockRevert");
    }
}

/**
 * @title FailingSignatureImplementation
 * @dev Mock implementation that always fails signature validation
 */
contract FailingSignatureImplementation is MockImplementation {
    /// @dev Always returns failure for signature validation
    function isValidSignature(
        bytes32,
        bytes calldata
    ) external pure override returns (bytes4) {
        return 0xffffffff;
    }
}

/**
 * @title RevertingIsValidSignatureImplementation
 * @dev Mock implementation that always reverts during signature validation
 */
contract RevertingIsValidSignatureImplementation is MockImplementation {
    /// @dev Always reverts during signature validation
    function isValidSignature(
        bytes32,
        bytes calldata
    ) external pure override returns (bytes4) {
        revert("SignatureValidationFailed");
    }
}

/**
 * @title RevertingInitializerMockImplementation
 * @dev Mock implementation that always reverts on initialization
 */
contract RevertingInitializerMockImplementation is MockImplementation {
    /// @dev Always reverts on initialization
    function initialize(address) public pure {
        revert("InitializerReverted");
    }
}

/**
 * @dev Mock implementation that returns ERC1271_MAGIC_VALUE with extra data
 */
contract MockImplementationWithExtraData is MockImplementation {
    function isValidSignature(
        bytes32,
        bytes memory
    ) public pure override returns (bytes4) {
        // Return magic value (0x1626ba7e) followed by extra data
        bytes32 returnValue = bytes32(bytes4(ERC1271_MAGIC_VALUE)) |
            bytes32(uint256(0xdeadbeef) << 32);
        assembly {
            // Need assembly to return more than 4 bytes from a function declared to return bytes4
            mstore(0x00, returnValue)
            return(0x00, 32)
        }
    }
}
