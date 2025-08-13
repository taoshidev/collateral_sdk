from bittensor.utils import is_valid_ss58_address, ss58_address_to_bytes
from eth_typing import ChecksumAddress
from web3 import Web3


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
