# Light Account

Light Account is an extension of `SimpleAccount` from [eth-infinitism/account-abstraction](https://github.com/eth-infinitism/account-abstraction).

Additional features include:

- ERC-1271 support
- Ownership transfers
- Namespaced storage

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
