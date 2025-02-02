# Aderyn Analysis Report

This report was generated by [Aderyn](https://github.com/Cyfrin/aderyn), a static analysis tool built by [Cyfrin](https://cyfrin.io), a blockchain security company. This report is not a substitute for manual audit or security review. It should not be relied upon for any purpose other than to assist in the identification of potential security vulnerabilities.
# Table of Contents

- [Summary](#summary)
  - [Files Summary](#files-summary)
  - [Files Details](#files-details)
  - [Issue Summary](#issue-summary)
- [High Issues](#high-issues)
  - [H-1: Delegatecall made by the function without checks on any adress.](#h-1-delegatecall-made-by-the-function-without-checks-on-any-adress)
- [Low Issues](#low-issues)
  - [L-1: Solidity pragma should be specific, not wide](#l-1-solidity-pragma-should-be-specific-not-wide)
  - [L-2: `public` functions not used internally could be marked `external`](#l-2-public-functions-not-used-internally-could-be-marked-external)
  - [L-3: Event is missing `indexed` fields](#l-3-event-is-missing-indexed-fields)
  - [L-4: PUSH0 is not supported by all chains](#l-4-push0-is-not-supported-by-all-chains) X
  - [L-5: Large literal values multiples of 10000 can be replaced with scientific notation](#l-5-large-literal-values-multiples-of-10000-can-be-replaced-with-scientific-notation)
  - [L-6: Internal functions called only once can be inlined](#l-6-internal-functions-called-only-once-can-be-inlined)
  - [L-7: Loop contains `require`/`revert` statements](#l-7-loop-contains-requirerevert-statements) X
  - [L-8: Costly operations inside loops.](#l-8-costly-operations-inside-loops) X


# Summary

## Files Summary

| Key | Value |
| --- | --- |
| .sol Files | 2 |
| Total nSLOC | 678 |


## Files Details

| Filepath | nSLOC |
| --- | --- |
| contracts/core/EntryPoint.sol | 602 |
| contracts/interfaces/IEntryPoint.sol | 76 |
| **Total** | **678** |


## Issue Summary

| Category | No. of Issues |
| --- | --- |
| High | 1 |
| Low | 8 |


# High Issues

## H-1: Delegatecall made by the function without checks on any adress.

Introduce checks on the address

<details><summary>1 Found Instances</summary>


- Found in contracts/core/EntryPoint.sol [Line: 796](contracts/core/EntryPoint.sol#L796)

	```solidity
	    function delegateAndRevert(address target, bytes calldata data) external {
	```

</details>



# Low Issues

## L-1: Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

<details><summary>2 Found Instances</summary>


- Found in contracts/core/EntryPoint.sol [Line: 2](contracts/core/EntryPoint.sol#L2)

	```solidity
	pragma solidity ^0.8.23;
	```

- Found in contracts/interfaces/IEntryPoint.sol [Line: 6](contracts/interfaces/IEntryPoint.sol#L6)

	```solidity
	pragma solidity >=0.7.5;
	```

</details>



## L-2: `public` functions not used internally could be marked `external`

Instead of marking a function as `public`, consider marking it as `external` if it is not used internally.

<details><summary>4 Found Instances</summary>


- Found in contracts/core/EntryPoint.sol [Line: 49](contracts/core/EntryPoint.sol#L49)

	```solidity
	    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
	```

- Found in contracts/core/EntryPoint.sol [Line: 174](contracts/core/EntryPoint.sol#L174)

	```solidity
	    function handleOps(
	```

- Found in contracts/core/EntryPoint.sol [Line: 208](contracts/core/EntryPoint.sol#L208)

	```solidity
	    function handleAggregatedOps(
	```

- Found in contracts/core/EntryPoint.sol [Line: 451](contracts/core/EntryPoint.sol#L451)

	```solidity
	    function getSenderAddress(bytes calldata initCode) public {
	```

</details>



## L-3: Event is missing `indexed` fields

Index event fields make the field more quickly accessible to off-chain tools that parse events. However, note that each index field costs extra gas during emission, so it's not necessarily best to index the maximum allowed per event (three fields). Each event should use three indexed fields if there are three or more fields, and gas usage is not particularly of concern for the events in question. If there are fewer than three fields, all of the fields should be indexed.

<details><summary>4 Found Instances</summary>


- Found in contracts/interfaces/IEntryPoint.sol [Line: 46](contracts/interfaces/IEntryPoint.sol#L46)

	```solidity
	    event AccountDeployed(
	```

- Found in contracts/interfaces/IEntryPoint.sol [Line: 60](contracts/interfaces/IEntryPoint.sol#L60)

	```solidity
	    event UserOperationRevertReason(
	```

- Found in contracts/interfaces/IEntryPoint.sol [Line: 74](contracts/interfaces/IEntryPoint.sol#L74)

	```solidity
	    event PostOpRevertReason(
	```

- Found in contracts/interfaces/IEntryPoint.sol [Line: 87](contracts/interfaces/IEntryPoint.sol#L87)

	```solidity
	    event UserOperationPrefundTooLow(
	```

</details>



## L-4: PUSH0 is not supported by all chains

Solc compiler version 0.8.20 switches the default target EVM version to Shanghai, which means that the generated bytecode will include PUSH0 opcodes. Be sure to select the appropriate EVM version in case you intend to deploy on a chain other than mainnet like L2 chains that may not support PUSH0, otherwise deployment of your contracts will fail.

<details><summary>2 Found Instances</summary>


- Found in contracts/core/EntryPoint.sol [Line: 2](contracts/core/EntryPoint.sol#L2)

	```solidity
	pragma solidity ^0.8.23;
	```

- Found in contracts/interfaces/IEntryPoint.sol [Line: 6](contracts/interfaces/IEntryPoint.sol#L6)

	```solidity
	pragma solidity >=0.7.5;
	```

</details>



## L-5: Large literal values multiples of 10000 can be replaced with scientific notation

Use `e` notation, for example: `1e18`, instead of its full numeric value.

<details><summary>1 Found Instances</summary>


- Found in contracts/core/EntryPoint.sol [Line: 39](contracts/core/EntryPoint.sol#L39)

	```solidity
	    uint256 private constant INNER_GAS_OVERHEAD = 10000;
	```

</details>



## L-6: Internal functions called only once can be inlined

Instead of separating the logic into a separate function, consider inlining the logic into the calling function. This can reduce the number of function calls and improve readability.

<details><summary>3 Found Instances</summary>


- Found in contracts/core/EntryPoint.sol [Line: 757](contracts/core/EntryPoint.sol#L757)

	```solidity
	    function getUserOpGasPrice(
	```

- Found in contracts/core/EntryPoint.sol [Line: 775](contracts/core/EntryPoint.sol#L775)

	```solidity
	    function getOffsetOfMemoryBytes(
	```

- Found in contracts/core/EntryPoint.sol [Line: 787](contracts/core/EntryPoint.sol#L787)

	```solidity
	    function getMemoryBytesFromOffset(
	```

</details>



## L-7: Loop contains `require`/`revert` statements

Avoid `require` / `revert` statements in a loop because a single bad item can cause the whole transaction to fail. It's better to forgive on fail and return failed elements post processing of the loop

<details><summary>1 Found Instances</summary>


- Found in contracts/core/EntryPoint.sol [Line: 215](contracts/core/EntryPoint.sol#L215)

	```solidity
	        for (uint256 i = 0; i < opasLen; i++) {
	```

</details>



## L-8: Costly operations inside loops.

Invoking `SSTORE`operations in loops may lead to Out-of-gas errors. Use a local variable to hold the loop computation result.

<details><summary>3 Found Instances</summary>


- Found in contracts/core/EntryPoint.sol [Line: 182](contracts/core/EntryPoint.sol#L182)

	```solidity
	            for (uint256 i = 0; i < opslen; i++) {
	```

- Found in contracts/core/EntryPoint.sol [Line: 239](contracts/core/EntryPoint.sol#L239)

	```solidity
	        for (uint256 a = 0; a < opasLen; a++) {
	```

- Found in contracts/core/EntryPoint.sol [Line: 245](contracts/core/EntryPoint.sol#L245)

	```solidity
	            for (uint256 i = 0; i < opslen; i++) {
	```

</details>



