from bittensor.sp_core import ss58_decode
from bittensor.wallets import is_valid_ss58_address
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

    # ss58_decode returns a hex string (no 0x prefix) of the 32-byte AccountId
    account_id_hex = ss58_decode(address)

    # Take the first 20 bytes (40 hex characters) of the AccountId32.
    # Refer to https://github.com/gztensor/precompile-examples/blob/3680e830f1a1e90a2328410fd86255b6b184d4b7/src/util/eth-helpers.js#L55
    return Web3.to_checksum_address(account_id_hex[:40])
