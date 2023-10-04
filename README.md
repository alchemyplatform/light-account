# Light Account

A simple ERC-4337 compatible smart contract account with a designated owner account.

Like [eth-infinitism](https://github.com/eth-infinitism/account-abstraction)'s `SimpleAccount`, but with the following changes:

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

## Generate Inspections

```bash
bash utils/inspect.sh
```

## Static Analysis

```bash
slither .
```
