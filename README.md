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
git+https://https://github.com/taoshidev/collateral_sdk.git@<VERSION>#egg=collateral_sdk
```
