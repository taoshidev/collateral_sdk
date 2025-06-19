import bittensor
import bittensor.utils
from eth_typing import ChecksumAddress
from web3 import Web3


def pubkey_to_h160(pubkey: str) -> ChecksumAddress:
    """
    Convert a public key to an H160 address.

    Args:
        pubkey (str): The public key to convert.

    Returns:
        ChecksumAddress: The corresponding H160 address.
    """

    if pubkey.startswith("0x") or pubkey.startswith("0X"):
        pubkey = pubkey[2:]

    # Take the first 20 bytes (40 hex characters) of the public key.
    address = "0x" + pubkey[:40]

    return Web3.to_checksum_address(address)


def ss58_to_h160(address: str) -> ChecksumAddress:
    """
    Convert an SS58 address to an H160 address.

    Args:
        address (str): The SS58 address to convert.

    Returns:
        ChecksumAddress: The corresponding H160 address.
    """

    pubkey_bytes = bittensor.utils.ss58_address_to_bytes(address)
    pubkey = pubkey_bytes.hex()

    return pubkey_to_h160(pubkey)
