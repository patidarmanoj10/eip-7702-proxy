// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

contract MockImplementation is UUPSUpgradeable {
    bytes4 constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    address public owner;
    bool public initialized;

    event Initialized(address owner);
    event MockFunctionCalled();

    error AlreadyInitialized();

    function initialize(address _owner) external virtual {
        if (initialized) revert AlreadyInitialized();
        owner = _owner;
        initialized = true;
        emit Initialized(_owner);
    }

    function mockFunction() external virtual {
        emit MockFunctionCalled();
    }

    function isValidSignature(
        bytes32,
        bytes calldata
    ) external pure virtual returns (bytes4) {
        return ERC1271_MAGIC_VALUE;
    }

    function _authorizeUpgrade(address) internal view override {
        require(msg.sender == owner, "Unauthorized");
    }
}

contract RevertingMockImplementation is MockImplementation {
    function isValidSignature(
        bytes32,
        bytes calldata
    ) external pure override returns (bytes4) {
        revert("Always reverts");
    }
}

contract RevertingInitializerMockImplementation is MockImplementation {
    function initialize(address) external pure override {
        revert("Initialize always reverts");
    }
}

contract RevertingMockFunctionImplementation is MockImplementation {
    function mockFunction() external pure override {
        revert("MockFunction always reverts");
    }
}

contract FailingSignatureImplementation is MockImplementation {
    bytes4 constant ERC1271_FAIL_VALUE = 0xffffffff;

    function isValidSignature(
        bytes32,
        bytes calldata
    ) external pure override returns (bytes4) {
        return ERC1271_FAIL_VALUE;
    }
}
