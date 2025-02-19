// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

/// @title NonceTracker
///
/// @notice A separate storage contract for securely tracking nonces for EIP-7702 proxies.
///
/// @dev This contract is used to track nonces for EIP-7702 proxies. It is separate from the storage location
///      of the 7702 account itself to prevent the nonce from being tampered with by other arbitrary delegates
///      of the account.
///
/// @author Coinbase (https://github.com/base/eip-7702-proxy)
contract NonceTracker {
    /// @notice Track nonces per-account to mitigate signature replayability
    mapping(address account => uint256 nonce) public nonces;

    /// @notice An account's nonce has been used
    event NonceUsed(address indexed account, uint256 nonce);

    /// @notice Consume a nonce for the caller
    ///
    /// @return nonce The nonce just used
    function useNonce() external returns (uint256 nonce) {
        nonce = nonces[msg.sender]++;
        emit NonceUsed(msg.sender, nonce);
    }
}
