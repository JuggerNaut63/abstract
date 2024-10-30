// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "../contracts/core/EntryPoint.sol";
import "../contracts/core/BaseAccount.sol";
import "../contracts/core/BasePaymaster.sol";
import "../contracts/interfaces/PackedUserOperation.sol";

contract EntryPointTest is Test {
    EntryPoint entryPoint;
    address addr1;
    address addr2;

    function setUp() public {
        entryPoint = new EntryPoint();
        addr1 = address(0x1);
        addr2 = address(0x2);
        vm.deal(addr1, 1 ether);
    }

    function testHandleOps() public {
        // Define ops as an array of PackedUserOperation
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);

        // Set the verificationGasLimit and callGasLimit
        uint256 verificationGasLimit = 300000; // Adjust this value based on your needs
        uint256 callGasLimit = 500000; // Set callGasLimit as needed

        // Pack the verificationGasLimit and callGasLimit into a bytes32
        bytes32 accountGasLimits = bytes32((verificationGasLimit << 128) | callGasLimit);

        // Simulate a user operation with valid data
        ops[0] = PackedUserOperation({
            sender: 0x0000000000000000000000000000000000000001,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: accountGasLimits,
            preVerificationGas: 200000, // Adjust if necessary
            gasFees: 0x000000000000000000000000000000000000000000000000000000003b9aca00,
            paymasterAndData: "",
            signature: new bytes(0) // Use an empty bytes array for the signature
        });

        // Mock the account's validateUserOp to always succeed
        vm.mockCall(addr1, abi.encodeWithSelector(IAccount.validateUserOp.selector), abi.encode(uint256(0)));

        // Ensure the account has enough deposit for prefund
        vm.prank(addr1);
        entryPoint.depositTo{value: 0.1 ether}(addr1);

        // Call handleOps
        entryPoint.handleOps(ops, payable(addr2));

        // Add assertions to verify the expected behavior
    }

    function testGetNonce() public view {
        uint256 nonce = entryPoint.getNonce(addr1, 0);
        assertEq(nonce, 0);
    }

    function testIncrementNonce() public {
        // Ensure the correct sender is used
        vm.prank(addr1);
        entryPoint.incrementNonce(0);

        uint256 nonce = entryPoint.getNonce(addr1, 0);
        assertEq(nonce, 1);
    }

function testReplayAttackWithSameNonce() public {
    // Define user operations with different keys but resulting in the same nonce
    PackedUserOperation[] memory ops = new PackedUserOperation[](1);

    // First operation with a small key
    uint192 key1 = 1;
    ops[0] = PackedUserOperation({
        sender: addr1,
        nonce: uint256(key1) << 64, // Use the small key in the nonce
        initCode: "",
        callData: "",
        accountGasLimits: bytes32((uint256(300000) << 128) | uint256(500000)),
        preVerificationGas: 200000,
        gasFees: 0x000000000000000000000000000000000000000000000000000000003b9aca00,
        paymasterAndData: "",
        signature: abi.encodePacked(uint256(0)) // Add a dummy signature
    });

    // Mock the account's validateUserOp to always succeed
    vm.mockCall(addr1, abi.encodeWithSelector(IAccount.validateUserOp.selector), abi.encode(uint256(0)));

    // Ensure the account has enough deposit for prefund
    vm.prank(addr1);
    entryPoint.depositTo{value: 0.1 ether}(addr1);

    // Call handleOps for the first operation
    entryPoint.handleOps(ops, payable(addr2));

    // Second operation with a large key that results in a different nonce
    uint192 key2 = uint192(2**64 + 1);
    ops[0].nonce = uint256(key2) << 64; // Use the large key in the nonce

    // Attempt to replay the same operation with a different nonce
    entryPoint.handleOps(ops, payable(addr2));

    // Third operation with a different key to ensure unique nonce
    uint192 key3 = uint192(2**64 + 2);
    ops[0].nonce = uint256(key3) << 64; // Use a different key in the nonce

    // Attempt to replay the same operation with a different nonce
    entryPoint.handleOps(ops, payable(addr2));
}

function testDifferentUsersSameKey() public {
    // Allocate Ether to both users
    vm.deal(addr1, 1 ether);
    vm.deal(addr2, 1 ether);

    // Define user operations for different users using the same key
    PackedUserOperation[] memory ops = new PackedUserOperation[](1);

    // Define a common key
    uint192 commonKey = 1;

    // First user operation
    ops[0] = PackedUserOperation({
        sender: addr1,
        nonce: uint256(commonKey) << 64, // Use the common key in the nonce
        initCode: "",
        callData: "",
        accountGasLimits: bytes32((uint256(300000) << 128) | uint256(500000)),
        preVerificationGas: 200000,
        gasFees: 0x000000000000000000000000000000000000000000000000000000003b9aca00,
        paymasterAndData: "",
        signature: abi.encodePacked(uint256(0)) // Add a dummy signature
    });

    // Mock the account's validateUserOp to always succeed for addr1
    vm.mockCall(addr1, abi.encodeWithSelector(IAccount.validateUserOp.selector), abi.encode(uint256(0)));

    // Ensure the account has enough deposit for prefund
    vm.prank(addr1);
    entryPoint.depositTo{value: 0.1 ether}(addr1);

    // Call handleOps for the first user
    entryPoint.handleOps(ops, payable(addr2));

    // Second user operation with the same key
    ops[0].sender = addr2; // Change the sender to addr2

    // Mock the account's validateUserOp to always succeed for addr2
    vm.mockCall(addr2, abi.encodeWithSelector(IAccount.validateUserOp.selector), abi.encode(uint256(0)));

    // Ensure the account has enough deposit for prefund
    vm.prank(addr2);
    entryPoint.depositTo{value: 0.1 ether}(addr2);

    // Call handleOps for the second user
    entryPoint.handleOps(ops, payable(addr2));

    // Add assertions to verify the expected behavior
    uint256 nonce1 = entryPoint.getNonce(addr1, commonKey);
    uint256 nonce2 = entryPoint.getNonce(addr2, commonKey);
    assertEq(nonce1, (1 << 64) + 1); // Ensure nonce for addr1 is incremented
    assertEq(nonce2, (1 << 64) + 1); // Ensure nonce for addr2 is incremented
}

function testSameUserSameKeyTwice() public {
    // Allocate Ether to the user
    vm.deal(addr1, 1 ether);

    // Define user operations for the same user using the key 2**65
    PackedUserOperation[] memory ops = new PackedUserOperation[](1);

    // Define the key as 2**65
    uint192 key = uint192(2**65);

    // First user operation
    ops[0] = PackedUserOperation({
        sender: addr1,
        nonce: uint256(key) << 64, // Use the key in the nonce
        initCode: "",
        callData: "",
        accountGasLimits: bytes32((uint256(300000) << 128) | uint256(500000)),
        preVerificationGas: 200000,
        gasFees: 0x000000000000000000000000000000000000000000000000000000003b9aca00,
        paymasterAndData: "",
        signature: abi.encodePacked(uint256(0)) // Add a dummy signature
    });

    // Mock the account's validateUserOp to always succeed
    vm.mockCall(addr1, abi.encodeWithSelector(IAccount.validateUserOp.selector), abi.encode(uint256(0)));

    // Ensure the account has enough deposit for prefund
    vm.prank(addr1);
    entryPoint.depositTo{value: 0.1 ether}(addr1);

    // Call handleOps for the first operation
    entryPoint.handleOps(ops, payable(addr2));

    // Increment the nonce for the second operation
    ops[0].nonce = (uint256(key) << 64) + 1; // Increment the sequence number part of the nonce

    // Call handleOps for the second operation with the incremented nonce
    entryPoint.handleOps(ops, payable(addr2));

    // Add assertions to verify the expected behavior
    uint256 nonce = entryPoint.getNonce(addr1, key);
    assertEq(nonce, (uint256(key) << 64) + 2); // Ensure nonce is incremented twice
}

function testHandleOpsWithDuplicateNonce() public {
    // Allocate Ether to the user
    vm.deal(addr1, 1 ether);

    // Define user operations for the same user
    PackedUserOperation[] memory ops = new PackedUserOperation[](1);

    // Define a key for the nonce
    uint192 key = uint192(1);

    // Get the current nonce for the key
    uint256 currentNonce = entryPoint.getNonce(addr1, key);

    // Mock the account's validateUserOp to always succeed
    vm.mockCall(addr1, abi.encodeWithSelector(IAccount.validateUserOp.selector), abi.encode(uint256(0)));

    // Ensure the account has enough deposit for prefund
    vm.prank(addr1);
    entryPoint.depositTo{value: 0.1 ether}(addr1);

    // Define the user operation with the current nonce
    ops[0] = PackedUserOperation({
        sender: addr1,
        nonce: currentNonce,
        initCode: "",
        callData: "",
        accountGasLimits: bytes32((uint256(300000) << 128) | uint256(500000)),
        preVerificationGas: 200000,
        gasFees: 0x000000000000000000000000000000000000000000000000000000003b9aca00,
        paymasterAndData: "",
        signature: abi.encodePacked(uint256(0)) // Add a dummy signature
    });

    // Call handleOps with a valid nonce
    entryPoint.handleOps(ops, payable(addr2));

    // Attempt to call handleOps again with the same nonce
    // Expect the operation to revert due to nonce reuse
    vm.expectRevert("Nonce already used");
    entryPoint.handleOps(ops, payable(addr2));
}
}