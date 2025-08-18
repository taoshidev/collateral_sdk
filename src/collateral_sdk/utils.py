import json
from pathlib import Path

from bittensor.utils import is_valid_ss58_address, ss58_address_to_bytes
from eth_keyfile.keyfile import create_keyfile_json, decode_keyfile_json
from eth_keyfile.keyfile import load_keyfile as load_keyfile_json
from eth_typing import ChecksumAddress
from web3 import Web3


def create_keyfile(keyfile_path: str | Path, private_key: str, password: str) -> None:
    """
    Create a keyfile at the specified path with the given private key and password.

    Args:
        keyfile_path (str | Path): The path where the keyfile will be created.
        private_key (str): The private key to be stored in the keyfile.
        password (str): The password to encrypt the keyfile.

    Returns:
        None
    """

    keyfile_path = Path(keyfile_path)
    keyfile_path.parent.mkdir(parents=True, exist_ok=True)

    if private_key.startswith("0x") or private_key.startswith("0X"):
        private_key = private_key[2:]

    keyfile = create_keyfile_json(bytes.fromhex(private_key), password.encode("utf-8"))  # pyright: ignore[reportArgumentType]

    with open(keyfile_path, "w") as f:
        json.dump(keyfile, f)


def load_keyfile(keyfile_path: str | Path, password: str) -> tuple[ChecksumAddress, bytes]:
    """
    Load a keyfile from the specified path and decrypt it with the given password.

    Args:
        keyfile_path (str | Path): The path to the keyfile to be loaded.
        password (str): The password to decrypt the keyfile.

    Returns:
        bytes: The decrypted private key as bytes.
    """

    keyfile_path = Path(keyfile_path)
    keyfile = load_keyfile_json(str(keyfile_path))

    address = Web3.to_checksum_address(keyfile.get("address"))
    private_key = decode_keyfile_json(keyfile, password.encode("utf-8"))  # pyright: ignore[reportArgumentType]

    return address, private_key


def ss58_to_h160(address: str) -> ChecksumAddress:
    """
    Convert an SS58 address to an H160 address (with EIP55 checksum).

    Args:
        address (str): An SS58 address to convert.

    Returns:
        ChecksumAddress: The corresponding H160 address with EIP55 checksum format.

    Caveat:
        This function converts an SS58 address to an H160 address by truncating the first 20 bytes of the AccountId32.
        This only applies to Subtensor substrate chain.
    """

    if not is_valid_ss58_address(address):
        raise ValueError(f"Invalid SS58 address: {address}")

    account_id_bytes = ss58_address_to_bytes(address)
    account_id_hex = account_id_bytes.hex()

    # Take the first 20 bytes (40 hex characters) of the AccountId32.
    # Refer to https://github.com/gztensor/precompile-examples/blob/3680e830f1a1e90a2328410fd86255b6b184d4b7/src/util/eth-helpers.js#L55
    return Web3.to_checksum_address(account_id_hex[:40])
