# Light Account

A simple ERC-4337 compatible smart contract account with a designated owner account. [Account Kit](https://accountkit.alchemy.com/introduction.html) is the easiest way to integrate Light Account.

## Features

Like [eth-infinitism](https://github.com/eth-infinitism/account-abstraction)'s [`SimpleAccount`](https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/samples/SimpleAccount.sol), but with the following changes:

1. Instead of the default storage slots, uses namespaced storage to avoid clashes when switching implementations.

2. Ownership can be transferred via `transferOwnership`, similar to the behavior of an `Ownable` contract. This is a simple single-step operation, so care must be taken to ensure that the ownership is being transferred to the correct address.

3. Supports [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) signature validation for both validating the signature on user operations and in exposing its own `isValidSignature` method. This only works when the owner of `LightAccount` also support ERC-1271.

   _ERC-4337's bundler validation rules limit the types of contracts that can be used as owners to validate user operation signatures. For example, the contract's `isValidSignature` function may not use any forbidden opcodes such as `TIMESTAMP` or `NUMBER`, and the contract may not be an ERC-1967 proxy as it accesses a constant implementation slot not associated with the account, violating storage access rules. This also means that the owner of a `LightAccount` may not be another `LightAccount` if you want to send user operations through a bundler._

4. Event `SimpleAccountInitialized` renamed to `LightAccountInitialized`.

5. Uses custom errors.

## Deployments

See the current deployments in [Deployments.md](./Deployments.md).

## Build

```bash
forge build
```

## Test

```bash
forge test -vvv
```

## Deploy

The deploy script supports any [wallet options](https://book.getfoundry.sh/reference/forge/forge-script#wallet-options---raw) provided by Foundry, including local private keys, mneumonics, hardware wallets, and remote signers. Append the chosen signing method's option to the field marked `[WALLET_OPTION]` in the following script command, and set the sender address in the field `[SENDER_ADDRESS]`.

```bash
forge script script/Deploy_LightAccountFactory.s.sol:Deploy_LightAccountFactory [WALLET_OPTION] --sender [SENDER_ADDRESS]--rpc-url [RPC_URL] -vvvv --broadcast --verify
```

Make sure the provided `RPC_URL` is set to an RPC for the chain you wish to deploy on.

## Generate Inspections

```bash
bash utils/inspect.sh
```

## Static Analysis

```bash
slither .
```
