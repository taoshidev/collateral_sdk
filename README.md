# README

## Prerequisites

1. Python (>= 3.10)

2. (Optional) Poetry (>= 2.0.0), this is necessary to run examples.

- You don't need to install `poetry` if you use this package as one of dependencies.
- Official installer: https://python-poetry.org/docs/#installation

## Setting up wallets

(On the miner side)

To create a new wallet,

```
btcli wallet create --no-use-password
```

Or to import from the known mnemonic

```
btcli wallet regen-coldkey --mnemonic <YOUR_MNEMONIC> --no-use-password
```

(On the validator side)

Same as the above, but this wallet should be the vault wallet for all collateral deposited.

## Running examples

First, install the requirements using `poetry`.

In terminal, type the following command.

```
poetry install
```

And then open one of the notebooks in the `exmaples/`, replace `REPLACE_ME` with the address and the private key of the contract's owner, and run the notebook. These notebooks show you how to use the SDK.

## Adding the SDK to dependencies

Add the following to `requirements.txt`.

```
git+https://github.com/taoshidev/collateral_sdk.git@<VERSION>#egg=collateral_sdk
```

## Using a self-hosted subtensor node

By default `CollateralManager` uses the public endpoints, which are rate limited. To route all
EVM and subtensor traffic through your own node, pass both endpoints:

```python
manager = CollateralManager(
    Network.MAINNET,
    evm_endpoint="http://127.0.0.1:9944",
    subtensor_endpoint="ws://127.0.0.1:9944",
)
```

The chain id, contract address, and netuid still come from `network`. The constructor checks that
`evm_endpoint` serves the network's chain id and raises `ValueError` if it does not, or if it cannot
be reached.
