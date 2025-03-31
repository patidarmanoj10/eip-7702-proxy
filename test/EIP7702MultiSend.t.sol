// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import {Test, console} from "forge-std/Test.sol";
import {FakeMultiSend} from "../src/FakeMultiSend.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {Vm} from "forge-std/Vm.sol";
import {MultiSend} from "../src/MultiSend.sol";
import {FakeMultiSend} from "../src/FakeMultiSend.sol";

contract MultiSendTest is Test {
    // Alice's address and private key (EOA with no initial contract code).
    address payable ALICE_ADDRESS =
        payable(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);
    uint256 constant ALICE_PK =
        0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;

    // Bob's address and private key (Bob will execute transactions on Alice's behalf).
    address constant BOB_ADDRESS = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;
    uint256 constant BOB_PK =
        0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;

    // The contract that Alice will delegate execution to.
    MultiSend public multisend;

    FakeMultiSend public fakeMultisend;

    // ERC-20 token contract for minting test tokens.
    MockERC20 public token;

    function setUp() public {
        // Deploy the delegation contract (Alice will delegate calls to this contract).
        multisend = new MultiSend();

        fakeMultisend = new FakeMultiSend();

        // Deploy an ERC-20 token contract where Alice is the minter.
        token = new MockERC20();
    }

    function testSignDelegationAndThenAttachDelegation() public {
        // Construct a single transaction call: Mint 100 tokens to Bob.
        MultiSend.Call[] memory calls = new MultiSend.Call[](1);
        bytes memory data = abi.encodeCall(MockERC20.mint, (BOB_ADDRESS, 100));
        calls[0] = MultiSend.Call({to: address(token), data: data, value: 0});
    
        // Alice signs a delegation allowing `implementation` to execute transactions on her behalf.
        Vm.SignedDelegation memory signedDelegation = vm.signDelegation(
            address(multisend),
            ALICE_PK
        );
      

        // Bob attaches the signed delegation from Alice and broadcasts it.
        vm.broadcast(BOB_PK);
        vm.attachDelegation(signedDelegation);
        console.log("after attach delegation");
        console.log("Nonce of Alice:", vm.getNonce(ALICE_ADDRESS));
        console.log("Nonce of Bob:", vm.getNonce(BOB_ADDRESS));
       

        // Verify that Alice's account now temporarily behaves as a smart contract.
        bytes memory code = address(ALICE_ADDRESS).code;
        require(code.length > 0, "no code written to Alice");

        MultiSend(ALICE_ADDRESS).setCounter(100);
          console.log("after counter");
          console.log("Nonce of Alice:", vm.getNonce(ALICE_ADDRESS));
        console.log("Nonce of Bob:", vm.getNonce(BOB_ADDRESS));

          MultiSend(ALICE_ADDRESS).setCounter(2);
          console.log("after counter");
          console.log("Nonce of Alice:", vm.getNonce(ALICE_ADDRESS));
        console.log("Nonce of Bob:", vm.getNonce(BOB_ADDRESS));
       
        MultiSend(ALICE_ADDRESS).setFlag(true);
        console.log("after set flag");
        console.log("Nonce of Alice:", vm.getNonce(ALICE_ADDRESS));
        console.log("Nonce of Bob:", vm.getNonce(BOB_ADDRESS));
       
        // As Bob, execute the transaction via Alice's temporarily assigned contract.
        MultiSend(ALICE_ADDRESS).execute(calls);
         console.log("after calls");
        console.log("Nonce of Alice:", vm.getNonce(ALICE_ADDRESS));
        console.log("Nonce of Bob:", vm.getNonce(BOB_ADDRESS));

        // Verify Bob successfully received 100 tokens.
        assertEq(token.balanceOf(BOB_ADDRESS), 100);


        console.log("MultiSend(ALICE_ADDRESS).counter()", MultiSend(ALICE_ADDRESS).counter());
        console.log("MultiSend(ALICE_ADDRESS).flag()", MultiSend(ALICE_ADDRESS).flag());


        signedDelegation = vm.signDelegation(
            address(fakeMultisend),
            ALICE_PK
        );

        // Bob attaches the signed delegation from Alice and broadcasts it.
        // vm.broadcast(BOB_PK);
        vm.attachDelegation(signedDelegation);
      
        console.log("FakeMultiSend(ALICE_ADDRESS).counter()", FakeMultiSend(ALICE_ADDRESS).counter());
         console.log("FakeMultiSend(ALICE_ADDRESS).flag()", FakeMultiSend(ALICE_ADDRESS).flag());
          console.log("FakeMultiSend(ALICE_ADDRESS).id()", FakeMultiSend(ALICE_ADDRESS).id());



        signedDelegation = vm.signDelegation(
            address(multisend),
            ALICE_PK
        );

        // Bob attaches the signed delegation from Alice and broadcasts it.
        // vm.broadcast(BOB_PK);
        vm.attachDelegation(signedDelegation);

        console.log("MultiSend(ALICE_ADDRESS).counter()", MultiSend(ALICE_ADDRESS).counter());
         console.log("MultiSend(ALICE_ADDRESS).flag()", MultiSend(ALICE_ADDRESS).flag());


    }
}
