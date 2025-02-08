// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {CoinbaseImplementationTest} from "./coinbaseImplementation.t.sol";
import {MockERC721} from "../mocks/MockERC721.sol";
import {MockERC1155} from "../mocks/MockERC1155.sol";
import {EIP7702Proxy} from "../../src/EIP7702Proxy.sol";

contract TokenReceiveTest is CoinbaseImplementationTest {
    MockERC721 public nft;
    MockERC1155 public multiToken;
    uint256 constant TOKEN_ID = 1;
    uint256 constant AMOUNT = 1;

    function setUp() public override {
        super.setUp();
        nft = new MockERC721();
        multiToken = new MockERC1155();
    }

    function test_canReceive_ERC721_afterInitialization() public {
        // Mint and transfer NFT
        nft.mint(address(this), TOKEN_ID);
        nft.safeTransferFrom(address(this), _eoa, TOKEN_ID);

        // Verify transfer succeeded
        assertEq(nft.ownerOf(TOKEN_ID), _eoa);
    }

    function test_canReceive_ERC1155_afterInitialization() public {
        // Mint tokens directly to a regular address first
        address regularAddress = makeAddr("regularHolder");
        multiToken.mint(regularAddress, TOKEN_ID, AMOUNT, "");

        // Then transfer to our smart wallet
        vm.prank(regularAddress);
        multiToken.safeTransferFrom(regularAddress, _eoa, TOKEN_ID, AMOUNT, "");

        // Verify transfer succeeded
        assertEq(multiToken.balanceOf(_eoa, TOKEN_ID), AMOUNT);
    }

    function test_succeeds_ERC721Transfer_beforeInitialization() public {
        // Deploy proxy without initializing
        address payable uninitProxy = payable(makeAddr("uninitProxy"));
        _deployProxy(uninitProxy);

        // Mint NFT
        nft.mint(address(this), TOKEN_ID);

        // Transfer should succeed
        nft.safeTransferFrom(address(this), uninitProxy, TOKEN_ID);

        // Verify transfer succeeded
        assertEq(nft.ownerOf(TOKEN_ID), uninitProxy);
    }

    function test_succeeds_ERC1155Transfer_beforeInitialization() public {
        // Deploy proxy without initializing
        address payable uninitProxy = payable(makeAddr("uninitProxy"));
        _deployProxy(uninitProxy);

        // Mint tokens to a regular address first
        address regularAddress = makeAddr("regularHolder");
        multiToken.mint(regularAddress, TOKEN_ID, AMOUNT, "");

        // Transfer should succeed
        vm.prank(regularAddress);
        multiToken.safeTransferFrom(
            regularAddress,
            uninitProxy,
            TOKEN_ID,
            AMOUNT,
            ""
        );

        // Verify transfer succeeded
        assertEq(multiToken.balanceOf(uninitProxy, TOKEN_ID), AMOUNT);
    }
}
