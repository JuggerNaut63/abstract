// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "../contracts/core/EntryPoint.sol";
import "../contracts/samples/SimpleAccountFactory.sol";
import "../contracts/test/TestCounter.sol";
import "../contracts/test/TestPaymasterAcceptAll.sol";
import "../contracts/test/TestRevertAccount.sol";
import "../contracts/test/TestWarmColdAccount.sol";
import "../contracts/test/TestPaymasterRevertCustomError.sol";
import "../contracts/test/TestSignatureAggregator.sol";
import "../contracts/test/TestAggregatedAccount.sol";
import "../contracts/test/TestAggregatedAccountFactory.sol";
import "../contracts/test/TestExpirePaymaster.sol";
import "../contracts/test/TestExpiryAccount.sol";
import "../contracts/test/MaliciousAccount.sol";
import "../contracts/interfaces/IEntryPoint.sol";
import "../contracts/interfaces/IStakeManager.sol";
import "../contracts/interfaces/INonceManager.sol";
import "../contracts/interfaces/IAccount.sol";
import "../contracts/interfaces/IAccountExecute.sol";
import "../contracts/interfaces/IPaymaster.sol";
import "../contracts/utils/Exec.sol";
import "../contracts/core/StakeManager.sol";
import "../contracts/core/SenderCreator.sol";
import "../contracts/core/Helpers.sol";
import "../contracts/core/NonceManager.sol";
import "../contracts/core/UserOperationLib.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract EntryPointTest is Test {
    EntryPoint entryPoint;
    SimpleAccountFactory simpleAccountFactory;
    TestCounter counter;
    TestPaymasterAcceptAll paymaster;
    TestRevertAccount testRevertAccount;
    TestWarmColdAccount testWarmColdAccount;
    TestPaymasterRevertCustomError testPaymasterRevertCustomError;
    TestSignatureAggregator testSignatureAggregator;
    TestAggregatedAccount testAggregatedAccount;
    TestAggregatedAccountFactory testAggregatedAccountFactory;
    TestExpirePaymaster testExpirePaymaster;
    TestExpiryAccount testExpiryAccount;
    MaliciousAccount maliciousAccount;

    address accountOwner;
    address payable account;
    address payable beneficiary;
    uint256 globalUnstakeDelaySec = 2;
    uint256 paymasterStake = 2 ether;

    function setUp() public {
        entryPoint = new EntryPoint();
        simpleAccountFactory = new SimpleAccountFactory(entryPoint);
        counter = new TestCounter();
        paymaster = new TestPaymasterAcceptAll(entryPoint);
        testRevertAccount = new TestRevertAccount(entryPoint);
        testWarmColdAccount = new TestWarmColdAccount(entryPoint);
        testPaymasterRevertCustomError = new TestPaymasterRevertCustomError(entryPoint);
        testSignatureAggregator = new TestSignatureAggregator();
        testAggregatedAccount = new TestAggregatedAccount(entryPoint, address(testSignatureAggregator));
        testAggregatedAccountFactory = new TestAggregatedAccountFactory(entryPoint, address(testSignatureAggregator));
        testExpirePaymaster = new TestExpirePaymaster(entryPoint);
        testExpiryAccount = new TestExpiryAccount(entryPoint);
        maliciousAccount = new MaliciousAccount(entryPoint);

        accountOwner = address(0x123);
        account = payable(address(0x456));
        beneficiary = payable(address(0x789));

        vm.deal(accountOwner, 10 ether);
        vm.deal(account, 10 ether);
        vm.deal(beneficiary, 10 ether);
    }

    function testDepositForTransferIntoEntryPoint() public {
        // Fund the sender address
        address sender = address(0xabc);
        vm.deal(sender, 1 ether);

        // Simulate the transfer
        vm.prank(sender);
        (bool success, ) = address(entryPoint).call{value: 1 ether}("");
        require(success, "Transfer failed");

        // Assert the deposit in EntryPoint
        uint256 expectedDeposit = 1 ether;
        assertEq(entryPoint.balanceOf(sender), expectedDeposit);
    }

    function testFailToStakeWithoutValue() public {
        vm.expectRevert("no stake specified");
        entryPoint.addStake(2);
    }

    function testFailToStakeWithoutDelay() public {
        vm.expectRevert("must specify unstake delay");
        entryPoint.addStake{value: 1 ether}(0);
    }

    function testFailToUnlock() public {
        vm.expectRevert("not staked");
        entryPoint.unlockStake();
    }

    function testStakeManagement() public {
        // Add stake
        entryPoint.addStake{value: 2 ether}(2);

        // Unlock the stake
        entryPoint.unlockStake();

        // Wait for the unstake delay to pass
        vm.warp(block.timestamp + 2);

        // Attempt to withdraw the stake
        entryPoint.withdrawStake(payable(address(0x0)));

        // Check that the stake is withdrawn
        uint256 stakeBalance = entryPoint.balanceOf(address(this));
        assertEq(stakeBalance, 0, "Stake not withdrawn correctly");
    }

function testAccountDepositAndWithdrawal() public {
    // Set up initial deposit
    uint256 initialDeposit = 1 ether;

    // Use the EntryPoint contract to add a deposit
    entryPoint.depositTo{value: initialDeposit}(account);

    // Check the deposit balance before withdrawal
    uint256 depositBalance = entryPoint.balanceOf(account);
    assertEq(depositBalance, initialDeposit, "Initial deposit not set correctly");

    // Ensure the account has sufficient funds before withdrawing
    require(depositBalance >= initialDeposit, "Insufficient funds for withdrawal");

    // Withdraw the deposit
    entryPoint.withdrawTo(account, initialDeposit);

    // Assert the final balance
    uint256 expectedBalance = 0;
    assertEq(entryPoint.balanceOf(account), expectedBalance, "Final balance not zero after withdrawal");
}

    function testSimulateValidation() public {
        // Implement test logic for simulateValidation
    }

    function testFlickeringAccountValidation() public {
        // Implement test logic for flickering account validation
    }

function test2DNonces() public {
    // Setup: Define user and keys
    address user = address(0x123);
    uint192 key1 = uint192(1);
    uint192 key2 = uint192(2);

    // Ensure user has sufficient funds
    uint256 initialDeposit = 1 ether;
    entryPoint.depositTo{value: initialDeposit}(user);

    // Retrieve nonces for the user with different keys
    uint256 nonce1 = entryPoint.getNonce(user, key1);
    uint256 nonce2 = entryPoint.getNonce(user, key2);

    // Extract sequence numbers from nonces
    uint64 seq1 = uint64(nonce1);
    uint64 seq2 = uint64(nonce2);

    // Log the sequence numbers
    emit log_named_uint("Sequence for User with key1", seq1);
    emit log_named_uint("Sequence for User with key2", seq2);

    // Ensure sequence numbers are different for different keys
    require(seq1 == 0, "Initial sequence for key1 should be 0");
    require(seq2 == 0, "Initial sequence for key2 should be 0");

    // Create user operations for the user with different keys
    PackedUserOperation[] memory ops = new PackedUserOperation[](2);
    ops[0] = PackedUserOperation({
        sender: user,
        nonce: nonce1,
        initCode: "", // Provide appropriate initCode
        callData: "", // Provide appropriate callData
        accountGasLimits: bytes32(uint256(21000) << 128 | 21000), // Example values packed
        preVerificationGas: 21000, // Example value
        gasFees: bytes32(uint256(1 gwei) << 128 | 1 gwei), // Example values packed
        paymasterAndData: "", // Provide appropriate paymasterAndData
        signature: "" // Provide appropriate signature
    });
    ops[1] = PackedUserOperation({
        sender: user,
        nonce: nonce2,
        initCode: "", // Provide appropriate initCode
        callData: "", // Provide appropriate callData
        accountGasLimits: bytes32(uint256(21000) << 128 | 21000), // Example values packed
        preVerificationGas: 21000, // Example value
        gasFees: bytes32(uint256(1 gwei) << 128 | 1 gwei), // Example values packed
        paymasterAndData: "", // Provide appropriate paymasterAndData
        signature: "" // Provide appropriate signature
    });

    // Call handleOps for both operations
    entryPoint.handleOps(ops, beneficiary);

    // Retrieve nonces again after operations
    uint256 newNonce1 = entryPoint.getNonce(user, key1);
    uint256 newNonce2 = entryPoint.getNonce(user, key2);

    // Extract new sequence numbers
    uint64 newSeq1 = uint64(newNonce1);
    uint64 newSeq2 = uint64(newNonce2);

    // Ensure sequence numbers have incremented correctly
    require(newSeq1 == seq1 + 1, "Sequence for key1 did not increment correctly");
    require(newSeq2 == seq2 + 1, "Sequence for key2 did not increment correctly");
}

    function testHandleOpsWithoutPaymaster() public {
        // Implement test logic for handleOps without paymaster
    }

    function testCreateAccount() public {
        // Implement test logic for create account
    }

    function testBatchMultipleRequests() public {
        // Implement test logic for batch multiple requests
    }

    function testAggregation() public {
        // Implement test logic for aggregation
    }

    function testHandleOpsWithPaymaster() public {
        // Implement test logic for handleOps with paymaster
    }

    function testValidationTimeRange() public {
        // Implement test logic for validation time-range
    }

    function testERC165Support() public {
        // Implement test logic for ERC-165 support
    }

function testNonceCollisionWithLargeKey() public {
    // Setup: Define users and keys
    address userA = address(0x123);
    address userB = address(0x456);
    uint192 collisionKey = uint192(2**65); // Use the same key for both users

    // Ensure both users have sufficient funds
    uint256 initialDeposit = 1 ether;
    entryPoint.depositTo{value: initialDeposit}(userA);
    entryPoint.depositTo{value: initialDeposit}(userB);

    // Retrieve nonces for both users using the same key
    uint256 nonceA = entryPoint.getNonce(userA, collisionKey);
    uint256 nonceB = entryPoint.getNonce(userB, collisionKey);

    // Log the nonces
    emit log_named_uint("Nonce for UserA with collision key", nonceA);
    emit log_named_uint("Nonce for UserB with collision key", nonceB);

    // Check if the nonces are treated as having the same value
    if (nonceA == nonceB) {
        emit log("Nonce collision detected!");
    } else {
        emit log("No collision detected.");
    }

    // Create user operations for UserA and UserB
    PackedUserOperation[] memory ops = new PackedUserOperation[](2);
    ops[0] = PackedUserOperation({
        sender: userA,
        nonce: nonceA,
        initCode: "", // Provide appropriate initCode
        callData: "", // Provide appropriate callData
        accountGasLimits: bytes32(uint256(21000) << 128 | 21000), // Example values packed
        preVerificationGas: 21000, // Example value
        gasFees: bytes32(uint256(1 gwei) << 128 | 1 gwei), // Example values packed
        paymasterAndData: "", // Provide appropriate paymasterAndData
        signature: "" // Provide appropriate signature
    });
    ops[1] = PackedUserOperation({
        sender: userB,
        nonce: nonceB,
        initCode: "", // Provide appropriate initCode
        callData: "", // Provide appropriate callData
        accountGasLimits: bytes32(uint256(21000) << 128 | 21000), // Example values packed
        preVerificationGas: 21000, // Example value
        gasFees: bytes32(uint256(1 gwei) << 128 | 1 gwei), // Example values packed
        paymasterAndData: "", // Provide appropriate paymasterAndData
        signature: "" // Provide appropriate signature
    });

    // Call handleOps for both users
    entryPoint.handleOps(ops, beneficiary);
}
}