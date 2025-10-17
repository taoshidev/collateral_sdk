# pyright: reportAssignmentType=false

import json
import time
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional

from async_substrate_interface.sync_substrate import ExtrinsicReceipt
from bittensor.core.errors import ChainError
from bittensor.core.subtensor_api import SubtensorApi
from bittensor.utils import is_valid_ss58_address
from bittensor.utils.balance import Balance
from bittensor_wallet import Wallet
from scalecodec import ss58_encode
from scalecodec.types import GenericCall, GenericExtrinsic, ScaleBytes
from web3 import Web3

from . import abi
from .errors import CriticalError, EVMError, SubtensorError
from .utils import ss58_to_h160


class Network(Enum):
    """
    Enum representing the different networks available for collateral operations.
    """

    LOCAL = auto()
    MAINNET = auto()
    TESTNET = auto()

    @property
    def evm_chain_id(self) -> int:
        if self.value == Network.LOCAL.value:
            return 945
        elif self.value == Network.MAINNET.value:
            return 964
        elif self.value == Network.TESTNET.value:
            return 945
        else:
            raise ValueError(f"Unknown network: {self}")

    @property
    def evm_endpoint(self) -> str:
        if self.value == Network.LOCAL.value:
            return "http://localhost:9944"
        elif self.value == Network.MAINNET.value:
            return "https://lite.chain.opentensor.ai"
        elif self.value == Network.TESTNET.value:
            return "https://test.chain.opentensor.ai"
        else:
            raise ValueError(f"Unknown network: {self}")

    @property
    def evm_program_address(self) -> str:
        if self.value == Network.LOCAL.value:
            raise ValueError("Program address is not set for a local network. Please set it manually.")
        elif self.value == Network.MAINNET.value:
            return "0xdb2e064f877b27Fcc83fb0DE98e718785aEdd072"
        elif self.value == Network.TESTNET.value:
            return "0x1a8C4c72D97b983C77BDa833883802145ecFD477"
        else:
            raise ValueError(f"Unknown network: {self}")

    @property
    def evm_contributor_program_address(self) -> str:
        if self.value == Network.LOCAL.value:
            raise ValueError("Contributor program address is not set for a local network. Please set it manually.")
        elif self.value == Network.MAINNET.value:
            return "0xdb2e064f877b27Fcc83fb0DE98e718785aEdd072"  # TODO: Update with actual contributor contract address
        elif self.value == Network.TESTNET.value:
            return "0x1a8C4c72D97b983C77BDa833883802145ecFD477"  # TODO: Update with actual contributor contract address
        else:
            raise ValueError(f"Unknown network: {self}")

    @property
    def netuid(self) -> int:
        if self.value == Network.LOCAL.value:
            raise ValueError("Netuid is not set for a local network. Please set it manually.")
        elif self.value == Network.MAINNET.value:
            return 8
        elif self.value == Network.TESTNET.value:
            return 116
        else:
            raise ValueError(f"Unknown network: {self}")

    @property
    def subtensor_network(self) -> str:
        if self.value == Network.LOCAL.value:
            return "local"
        elif self.value == Network.MAINNET.value:
            return "finney"
        elif self.value == Network.TESTNET.value:
            return "test"
        else:
            raise ValueError(f"Unknown network: {self}")


class CollateralManager:
    """
    A class to manage collateral operations on the PTN network.
    Supports both regular collateral operations and contributor-based collateral operations.

    Args:
        network (Network): The network to use for collateral operations. Defaults to Network.TESTNET.
        program_address (Optional[str]): The address of the EVM contract for collateral operations.
                                         Defaults to the already-deployed and trusted program address.
        contributor_program_address (Optional[str]): The address of the EVM contract for contributor operations.
                                                 Defaults to the already-deployed and trusted contributor program address.
    """

    def __init__(
        self,
        network: Network = Network.TESTNET,
        program_address: Optional[str] = None,
        contributor_program_address: Optional[str] = None,
    ):
        with open(Path(abi.__path__[0]) / "Collateral.abi.json", "r") as f:
            self.abi: Any = json.load(f)

        with open(Path(abi.__path__[0]) / "CollateralContributor.abi.json", "r") as f:
            self.contributor_abi: Any = json.load(f)

        if program_address is not None:
            try:
                program_address = Web3.to_checksum_address(program_address)
                web3 = Web3(Web3.HTTPProvider(network.evm_endpoint))
                contract = web3.eth.contract(program_address, abi=self.abi)
                contract.functions.getTotalCollateral().call()
            except Exception:
                raise ValueError(f"Invalid program address: {program_address}")

        if contributor_program_address is not None:
            try:
                contributor_program_address = Web3.to_checksum_address(contributor_program_address)
                web3 = Web3(Web3.HTTPProvider(network.evm_endpoint))
                contract = web3.eth.contract(contributor_program_address, abi=self.contributor_abi)
                contract.functions.totalCollateral().call()
            except Exception:
                raise ValueError(f"Invalid contributor program address: {contributor_program_address}")

        self.network = network
        self.program_address = program_address or network.evm_program_address
        self.contributor_program_address = contributor_program_address or network.evm_contributor_program_address
        self._subtensor_api = None

    @property
    def subtensor_api(self):
        if self._subtensor_api is None:
            self._subtensor_api = SubtensorApi(network=self.network.subtensor_network)
        return self._subtensor_api

    @property
    def web3(self) -> Web3:
        """Get Web3 instance (cached for performance)."""
        if not hasattr(self, "_web3") or self._web3 is None:
            self._web3 = Web3(Web3.HTTPProvider(self.network.evm_endpoint))
        return self._web3

    @property
    def collateral_contract(self):
        """Get main collateral contract instance (cached for performance)."""
        if not hasattr(self, "_collateral_contract") or self._collateral_contract is None:
            self._collateral_contract = self.web3.eth.contract(self.program_address, abi=self.abi)
        return self._collateral_contract

    @property
    def contributor_contract(self):
        """Get contributor collateral contract instance (cached for performance)."""
        if not hasattr(self, "_contributor_contract") or self._contributor_contract is None:
            self._contributor_contract = self.web3.eth.contract(
                self.contributor_program_address, abi=self.contributor_abi
            )
        return self._contributor_contract

    def _get_stake_added_amount(self, events: list[dict]) -> Balance:
        """
        Extract the stake added amount from the triggered events.

        Args:
            events (list[dict]): The list of triggered events.

        Returns:
            Balance: The stake added amount in Rao unit.
        """

        try:
            stake_added_event = next((ev for ev in events if ev["event"]["event_id"] == "StakeAdded"))
            stake_added_amount = stake_added_event["event"]["attributes"][3]
        except (IndexError, KeyError, StopIteration):
            raise ValueError(f"Failed to extract the stake added amount from the triggered events: {events}")

        return Balance.from_rao(
            stake_added_amount - 1,  # -1 is temporary fix for accuracy. Without this, the balance may be off by 1 Rao.
            netuid=self.network.netuid,
        )

    def balance_of(self, address: str) -> int:
        """
        Get the balance of the deposited alpha tokens for the given SS58 address.

        Args:
            address (str): The SS58 address to check the balance for.

        Returns:
            int: The balance of the address in Rao unit.
        """

        if not is_valid_ss58_address(address):
            raise ValueError(f"Invalid SS58 address: {address}")

        balance = self.collateral_contract.functions.balanceOf(ss58_to_h160(address)).call()
        return balance

    def create_stake_transfer_extrinsic(
        self,
        amount: int,  # pyright: ignore[reportRedeclaration]
        dest: str,
        source_stake: str,
        source_wallet: Wallet,
        source_netuid: Optional[int] = None,
        dest_netuid: Optional[int] = None,
        wallet_password: Optional[str] = None,
    ) -> GenericExtrinsic:
        """
        Create a stake transfer extrinsic for the specified amount and destination.

        Args:
            amount (int): The amount of alpha tokens to transfer in Rao unit.
            dest (str): The destination SS58 address to transfer the stake to.
            source_stake (str): The source stake's SS58 address to transfer.
            source wallet (Wallet): The source wallet to transfer the stake from.
            source_netuid (Optional[int]): The source netuid for the transfer. Defaults to 8 for Network.MAINET and 116 for Network.TESTNET.
            dest_netuid (Optional[int]): The destination netuid for the transfer. Defaults to 8 for Network.MAINET and 116 for Network.TESTNET.
            wallet_password (Optional[str]): The password for the source wallet.

        Returns:
            extrinsic: The signed extrinsic for the stake transfser.
        """

        if amount <= 0:
            raise ValueError(f"Amount must be greater than zero: {amount}")

        if not is_valid_ss58_address(source_stake):
            raise ValueError(f"Invalid stake address: {source_stake}")

        if not is_valid_ss58_address(dest):
            raise ValueError(f"Invalid destination address: {dest}")

        if source_netuid is None:
            source_netuid = self.network.netuid

        if dest_netuid is None:
            dest_netuid = self.network.netuid

        amount: Balance = Balance.from_rao(amount, netuid=source_netuid)

        staked_amount: Balance = self.subtensor_api.staking.get_stake(
            coldkey_ss58=source_wallet.coldkeypub.ss58_address,
            hotkey_ss58=source_stake,
            netuid=source_netuid,
        )

        if amount > staked_amount:
            raise ValueError(f"Insufficient balance: {staked_amount}, requested: {amount}")

        call: GenericCall = self.subtensor_api._subtensor.substrate.compose_call(
            call_module="SubtensorModule",
            call_function="transfer_stake",
            call_params={
                "destination_coldkey": dest,
                "hotkey": source_stake,
                "origin_netuid": source_netuid,
                "destination_netuid": dest_netuid,
                "alpha_amount": amount.rao,
            },
        )

        extrinsic: GenericExtrinsic = self.subtensor_api._subtensor.substrate.create_signed_extrinsic(
            call=call,
            keypair=source_wallet.get_coldkey(wallet_password) if wallet_password else source_wallet.coldkey,
        )

        return extrinsic

    def decode_extrinsic(self, data: bytearray) -> GenericExtrinsic:
        """
        Decode the extrinsic from a hex string.

        Args:
            data (bytearray): The encoded extrinsic to decode.

        Returns:
            GenericExtrinsic: The decoded extrinsic.
        """

        extrinsic = GenericExtrinsic(
            data=ScaleBytes(data),
            metadata=self.subtensor_api.substrate.metadata,
            runtime_config=self.subtensor_api.substrate.runtime_config,
        )
        extrinsic.decode()

        return extrinsic

    def encode_extrinsic(self, extrinsic: GenericExtrinsic) -> bytearray:
        """
        Encode the extrinsic to a hex string.

        Args:
            extrinsic (GenericExtrinsic): The extrinsic to encode.

        Returns:
            bytesarray: The encoded extrinsic as a bytearray.
        """

        return extrinsic.data.data

    def deposit(
        self,
        extrinsic: GenericExtrinsic,
        source_hotkey: str,
        vault_stake: str,
        vault_wallet: Wallet,
        owner_address: str,
        owner_private_key: str,
        wallet_password: Optional[str] = None,
        max_backoff: float = 30.0,
        max_retries: int = 3,
    ) -> Balance:
        """
        Submit the extrinsic to the Subtensor network and deposit the alpha tokens into the EVM contract.
        This function should be called on the owner validator side.

        Args:
            extrinsic (GenericExtrinsic): The signed extrinsic for the stake transfer.
            source_hotkey (str): The source miner hotkey to deposit from.
            vault_stake (str): The stake's SS58 address of the vault to deposit the alpha tokens to.
            vault_wallet (Wallet): The wallet of the vault.
            owner_address (str): The owner address the EVM contract.
            owner_private_key (str): The private key of the owner.
            wallet_password (Optional[str]): The password for the source wallet.
            max_backoff (float): The maximum backoff time in seconds for retries. Defaults to 30.0.
            max_retries (int): The maximum number of attempts to retry. Defaults to 3.

        Returns:
            Balance: The amount of alpha tokens deposited.

        CAUTION:
            This method is assumed to be called from a trusted node such as a owner/super validator.
            The owner/super validator should store the private key in a secure location, load and pass it to this method.
            NEVER, NEVER expose the private key to the public!

        IMPORTANT:
            If a critical error occurs, log the error and transfer the stake back to the source address manually!

        """

        origin_coldkey = (
            ss58_encode((extrinsic["address"].value))
            if extrinsic["address"].value.startswith("0x") or extrinsic["address"].value.startswith("0X")
            else extrinsic["address"].value
        )

        call = extrinsic["call"]
        module_name = call["call_module"]["name"].value
        function_name = call["call_function"]["name"].value

        if not (module_name == "SubtensorModule" and function_name == "transfer_stake"):
            raise ValueError(
                f"Invalid extrinsic: expected 'SubtensorModule.transfer_stake', got '{module_name}.{function_name}'"
            )

        if isinstance(call_args := extrinsic["call"]["call_args"], dict):
            destination_coldkey = call_args["destination_coldkey"].value
            destination_netuid = call_args["destination_netuid"].value
            origin_hotkey = call_args["hotkey"].value
            origin_netuid = call_args["origin_netuid"].value
        else:
            try:
                call_args = extrinsic.value["call"]["call_args"]  # pyright: ignore[reportOptionalSubscript]
                destination_coldkey = next(arg for arg in call_args if arg["name"] == "destination_coldkey")["value"]
                destination_netuid = next(arg for arg in call_args if arg["name"] == "destination_netuid")["value"]
                origin_hotkey = next(arg for arg in call_args if arg["name"] == "hotkey")["value"]
                origin_netuid = next(arg for arg in call_args if arg["name"] == "origin_netuid")["value"]
            except StopIteration:
                raise ValueError("Invalid extrinsic: missing required call arguments")

        if destination_coldkey != vault_wallet.coldkeypub.ss58_address:
            raise ValueError(
                f"The extrinsic's destination {destination_coldkey} does not match the vault wallet {vault_wallet.coldkeypub.ss58_address}"
            )

        if destination_netuid != self.network.netuid:
            raise ValueError(
                f"The extrinsic's destination netuid {destination_netuid} does not match the network's netuid {self.network.netuid}"
            )

        if origin_hotkey != source_hotkey:
            raise ValueError(
                f"The extrinsic's origin hotkey {origin_hotkey} does not match the source hotkey {source_hotkey}"
            )

        if origin_netuid != self.network.netuid:
            raise ValueError(
                f"The extrinsic's origin netuid {origin_netuid} does not match the network's netuid {self.network.netuid}"
            )

        # 1. Transfer the stake to the vault wallet.
        try:
            # Default RPC retries is 5 and RPC timeout is 60 seconds, which are configured in SubstrateInterface's __init__().
            # No need to retry login here.
            result: ExtrinsicReceipt = self.subtensor_api._subtensor.substrate.submit_extrinsic(
                extrinsic,
                wait_for_inclusion=True,
            )

            if result.is_success:
                try:
                    stake_added = self._get_stake_added_amount(result.triggered_events)
                except ValueError:
                    raise CriticalError("A stake has been transferred, but the amount is unknown")
            else:
                raise ChainError.from_error(result.error_message)

        except CriticalError:
            raise
        except Exception as e:
            raise SubtensorError(f"Failed to transfer the stake to the vault wallet: {e}") from e

        # 2. Move the stake to the vault's stake address.
        if origin_hotkey != vault_stake:
            try:
                move_call: GenericCall = self.subtensor_api._subtensor.substrate.compose_call(
                    call_module="SubtensorModule",
                    call_function="move_stake",
                    call_params={
                        "origin_hotkey": origin_hotkey,
                        "origin_netuid": self.network.netuid,
                        "destination_hotkey": vault_stake,
                        "destination_netuid": self.network.netuid,
                        "alpha_amount": stake_added.rao,
                    },
                )

                move_extrinsic: GenericExtrinsic = self.subtensor_api._subtensor.substrate.create_signed_extrinsic(
                    call=move_call,
                    keypair=vault_wallet.get_coldkey(wallet_password) if wallet_password else vault_wallet.coldkey,
                )

                result: ExtrinsicReceipt = self.subtensor_api._subtensor.substrate.submit_extrinsic(
                    move_extrinsic,
                    wait_for_inclusion=True,
                )

                if result.is_success:
                    try:
                        stake_added = self._get_stake_added_amount(result.triggered_events)
                    except ValueError:
                        raise CriticalError("A stake has been transferred and moved, but the amount is unknown")
                else:
                    raise ChainError.from_error(result.error_message)

            except CriticalError:
                raise
            except Exception as e:
                # 3. Revert the stake transfer if the stake move fails.
                try:
                    revert_extrinsic: GenericExtrinsic = self.create_stake_transfer_extrinsic(
                        amount=stake_added.rao,
                        source_stake=origin_hotkey,
                        source_wallet=vault_wallet,
                        dest=origin_coldkey,
                        wallet_password=wallet_password,
                    )

                    result: ExtrinsicReceipt = self.subtensor_api._subtensor.substrate.submit_extrinsic(
                        revert_extrinsic,
                        wait_for_inclusion=True,
                    )

                    if not result.is_success:
                        raise ChainError.from_error(result.error_message)

                except Exception as e:
                    # When the revert fails, raise a critical error.
                    raise CriticalError(f"Failed to revert the stake transfer: {e}") from e

                # After reverting the stake transfer, raise an error for the stake move failure.
                raise SubtensorError(f"Failed to move the stake to the vault's stake address: {e}") from e

        # 4. Deposit the collateral into the EVM contract.
        for i in range(max_retries):
            try:
                tx = self.collateral_contract.functions.deposit(
                    ss58_to_h160(source_hotkey), stake_added.rao
                ).build_transaction(
                    {
                        "chainId": self.network.evm_chain_id,
                        "from": owner_address,
                        "nonce": self.web3.eth.get_transaction_count(owner_address, block_identifier="pending"),  # pyright: ignore[reportArgumentType]
                    }
                )

                signed_tx = self.web3.eth.account.sign_transaction(tx, private_key=owner_private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

                if receipt["status"] == 1:
                    break
                else:
                    raise RuntimeError(
                        f"Transaction failed: {tx_hash.hex()}" if tx_hash in dir() else "Transaction failed"
                    )

            except Exception as e:
                if i < max_retries - 1:
                    time.sleep(min(2**i, max_backoff))
                    continue
                else:
                    # 4. Revert the stake transfer if deposit in the EVM fails.
                    try:
                        revert_extrinsic: GenericExtrinsic = self.create_stake_transfer_extrinsic(
                            amount=stake_added.rao,
                            source_stake=vault_stake,
                            source_wallet=vault_wallet,
                            dest=origin_coldkey,
                            wallet_password=wallet_password,
                        )

                        result: ExtrinsicReceipt = self.subtensor_api._subtensor.substrate.submit_extrinsic(
                            revert_extrinsic,
                            wait_for_inclusion=True,
                        )

                        if not result.is_success:
                            raise ChainError.from_error(result.error_message)

                    except Exception as e:
                        # When the revert fails, raise a critical error.
                        raise CriticalError(f"Failed to revert the stake transfer: {e}") from e

                    # After reverting the stake transfer, raise an error for the deposit failure.
                    raise EVMError(f"Failed to deposit into the EVM contract: {e}") from e

        return stake_added

    def force_deposit(
        self,
        address: str,
        amount: int,
        owner_address: str,
        owner_private_key: str,
        max_backoff: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        """
        Force deposit the specified amount of alpha tokens into the EVM contract without a stake transfer.
        This function should be called on the owner validator side.

        Args:
            address (str): The SS58 address to deposit to.
            amount (int): The amount of alpha tokens to deposit in Rao unit.
            owner_address (str): The owner address the EVM contract.
            owner_private_key (str): The private key of the owner.
            max_backoff (float): The maximum backoff time in seconds for retries. Defaults to 30.0.
            max_retries (int): The maximum number of attempts to retry. Defaults to 3

        Returns:
            None

        CAUTION:
            This method is assumed to be called from a trusted node such as a owner/super validator.
            The owner/super validator should store the private key in a secure location, load and pass it to this method.
            NEVER, NEVER expose the private key to the public!
        """

        if not is_valid_ss58_address(address):
            raise ValueError(f"Invalid SS58 address: {address}")

        for i in range(max_retries):
            try:
                tx = self.collateral_contract.functions.deposit(ss58_to_h160(address), amount).build_transaction(
                    {
                        "chainId": self.network.evm_chain_id,
                        "from": owner_address,
                        "nonce": self.web3.eth.get_transaction_count(owner_address),  # pyright: ignore[reportArgumentType]
                    }
                )

                signed_tx = self.web3.eth.account.sign_transaction(tx, private_key=owner_private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

                if receipt["status"] == 1:
                    break
                else:
                    raise RuntimeError(
                        f"Transaction failed: {tx_hash.hex()}" if tx_hash in dir() else "Transaction failed"
                    )

            except Exception as e:
                if i < max_retries - 1:
                    time.sleep(min(2**i, max_backoff))
                    continue
                else:
                    raise EVMError(f"Failed to force deposit into the EVM contract: {e}") from e

    def force_withdraw(
        self,
        address: str,
        amount: int,
        owner_address: str,
        owner_private_key: str,
        max_backoff: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        """
        Force withdraw the specified amount of alpha tokens from the EVM contract without a stake transfer.
        This function should be called on the owner validator side.

        Args:
            address (str): The SS58 address to withdraw from.
            amount (int): The amount of alpha tokens to withdraw in Rao unit.
            owner_address (str): The owner address the EVM contract.
            owner_private_key (str): The private key of the owner.
            max_backoff (float): The maximum backoff time in seconds for retries. Defaults to 30.0.
            max_retries (int): The maximum number of attempts to retry. Defaults to 3

        Returns:
            None

        CAUTION:
            This method is assumed to be called from a trusted node such as a owner/super validator.
            The owner/super validator should store the private key in a secure location, load and pass it to this method.
            NEVER, NEVER expose the private key to the public!
        """

        if not is_valid_ss58_address(address):
            raise ValueError(f"Invalid SS58 address: {address}")

        for i in range(max_retries):
            try:
                tx = self.collateral_contract.functions.withdraw(ss58_to_h160(address), amount).build_transaction(
                    {
                        "chainId": self.network.evm_chain_id,
                        "from": owner_address,
                        "nonce": self.web3.eth.get_transaction_count(owner_address),  # pyright: ignore[reportArgumentType]
                    }
                )

                signed_tx = self.web3.eth.account.sign_transaction(tx, private_key=owner_private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

                if receipt["status"] == 1:
                    break
                else:
                    raise RuntimeError(
                        f"Transaction failed: {tx_hash.hex()}" if tx_hash in dir() else "Transaction failed"
                    )

            except Exception as e:
                if i < max_retries - 1:
                    time.sleep(min(2**i, max_backoff))
                    continue
                else:
                    raise EVMError(f"Failed to force withdraw from the EVM contract: {e}") from e

    def get_slashed_collateral(self) -> int:
        """
        Get the total amount of slashed collateral in the EVM contract.

        Returns:
            int: The total amount of slashed collateral in Rao unit.
        """

        balance = self.collateral_contract.functions.slashedCollateral().call()
        return balance

    def get_total_collateral(self) -> int:
        """
        Get the total amount of collateral in the EVM contract.

        Returns:
            int: The total amount of collateral in Rao unit.
        """

        balance = self.collateral_contract.functions.totalCollateral().call()
        return balance

    def slash(
        self,
        address: str,
        amount: int,  # pyright: ignore[reportRedeclaration]
        owner_address: str,
        owner_private_key: str,
        max_backoff: float = 30.0,
        max_retries: int = 3,
    ) -> Balance:
        """
        Slash the specified amount of alpha tokens from the EVM contract.
        This function should be called on the owner validator side.

        Args:
            address (str): The SS58 address to slash from.
            amount (int): The amount of alpha tokens to slash in Rao unit.
            owner_address (str): The owner address the EVM contract.
            owner_private_key (str): The private key of the owner.
            max_backoff (float): The maximum backoff time in seconds for retries. Defaults to 30.0.
            max_retries (int): The maximum number of attempts to retry. Defaults to 3.

        Returns:
            Balance: The amount of alpha tokens slashed.

        CAUTION:
            This method is assumed to be called from a trusted node such as a owner/super validator.
            The owner/super validator should store the private key in a secure location, load and pass it to this method.
            NEVER, NEVER expose the private key to the public!
        """

        if not is_valid_ss58_address(address):
            raise ValueError(f"Invalid SS58 address: {address}")

        if amount <= 0:
            raise ValueError(f"Amount must be greater than zero: {amount}")

        amount: Balance = Balance.from_rao(amount, netuid=self.network.netuid)

        if amount > (balance := Balance.from_rao(self.balance_of(address), netuid=self.network.netuid)):
            raise ValueError(f"Insufficient balance: {balance}, requested: {amount}")

        for i in range(max_retries):
            try:
                tx = self.collateral_contract.functions.slash(ss58_to_h160(address), amount.rao).build_transaction(
                    {
                        "chainId": self.network.evm_chain_id,
                        "from": owner_address,
                        "nonce": self.web3.eth.get_transaction_count(owner_address),  # pyright: ignore[reportArgumentType]
                    }
                )

                signed_tx = self.web3.eth.account.sign_transaction(tx, private_key=owner_private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

                if receipt["status"] == 1:
                    break
                else:
                    raise RuntimeError(
                        f"Transaction failed: {tx_hash.hex()}" if tx_hash in dir() else "Transaction failed"
                    )

            except Exception as e:
                if i < max_retries - 1:
                    time.sleep(min(2**i, max_backoff))
                    continue
                else:
                    raise EVMError(f"Failed to slash from the EVM contract: {e}") from e

        return amount

    def withdraw(
        self,
        amount: int,  # pyright: ignore[reportRedeclaration]
        source_coldkey: str,
        source_hotkey: str,
        vault_stake: str,
        vault_wallet: Wallet,
        owner_address: str,
        owner_private_key: str,
        wallet_password: Optional[str] = None,
        max_backoff: float = 30.0,
        max_retries: int = 3,
    ) -> Balance:
        """
        Submit the extrinsic to the Subtensor network and withdraw the alpha tokens from the EVM contract.
        This function should be called on the owner validator side.

        Args:
            amount (int): The alpha token amount to withdraw in Rao unit.
            source_coldkey: (str): The source miner coldkey to withdraw the alpha tokens.
            source_hotkey (str): The source miner hotkey to withdraw the alpha tokens.
            vault_stake (str): The stake's SS58 address of the vault to withdraw the alpha tokens from.
            vault_wallet (Wallet): The wallet of the vault.
            owner_address (str): The owner address the EVM contract.
            owner_private_key (str): The private key of the owner.
            wallet_password (Optional[str]): The password for the source wallet.
            max_backoff (float): The maximum backoff time in seconds for retries. Defaults to 30.0.
            max_retries (int): The maximum number of attempts to retry. Defaults to 3.

        Returns:
            Balance: The amount of alpha tokens withdrawn.

        CAUTION:
            This method is assumed to be called from a trusted node such as a owner/super validator.
            The owner/super validator should store the private key in a secure location, load and pass it to this method.
            NEVER, NEVER expose the private key to the public!

        IMPORTANT:
            If a critical error occurs, log the error and force deposit the withdrawn amount back to the destination address manually!
        """

        if amount <= 0:
            raise ValueError(f"Amount must be greater than zero: {amount}")

        if not is_valid_ss58_address(source_coldkey):
            raise ValueError(f"Invalid destination SS58 address: {source_coldkey}")

        if not is_valid_ss58_address(source_hotkey):
            raise ValueError(f"Invalid source SS58 address: {source_hotkey}")

        if not is_valid_ss58_address(vault_stake):
            raise ValueError(f"Invalid stake SS58 address: {vault_stake}")

        # if self.subtensor_api.wallets.get_hotkey_owner(vault_stake) != vault_wallet.coldkeypub.ss58_address:
        #     raise ValueError(
        #         f"The stake {vault_stake} does not belong to the vault wallet {vault_wallet.coldkeypub.ss58_address}"
        #     )

        amount: Balance = Balance.from_rao(amount, netuid=self.network.netuid)

        if amount > (balance := Balance.from_rao(self.balance_of(source_hotkey), netuid=self.network.netuid)):
            raise ValueError(f"Insufficient balance: {balance}, requested: {amount}")

        # 1. Withdraw the collateral from the EVM contract.
        for i in range(max_retries):
            try:
                tx = self.collateral_contract.functions.withdraw(
                    ss58_to_h160(source_hotkey), amount.rao
                ).build_transaction(
                    {
                        "chainId": self.network.evm_chain_id,
                        "from": owner_address,
                        "nonce": self.web3.eth.get_transaction_count(owner_address),  # pyright: ignore[reportArgumentType]
                    }
                )

                signed_tx = self.web3.eth.account.sign_transaction(tx, private_key=owner_private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

                if receipt["status"] == 1:
                    break
                else:
                    raise RuntimeError(
                        f"Transaction failed: {tx_hash.hex()}" if tx_hash in dir() else "Transaction failed"
                    )

            except Exception as e:
                if i < max_retries - 1:
                    time.sleep(min(2**i, max_backoff))
                    continue
                else:
                    raise EVMError(f"Failed to withdraw from the EVM contract: {e}") from e

        # 2. Transfer the stake to the source coldkey.
        try:
            transfer_extrinsic: GenericExtrinsic = self.create_stake_transfer_extrinsic(
                amount=amount.rao,
                source_stake=vault_stake,
                source_wallet=vault_wallet,
                dest=source_coldkey,
                wallet_password=wallet_password,
            )

            result: ExtrinsicReceipt = self.subtensor_api._subtensor.substrate.submit_extrinsic(
                transfer_extrinsic,
                wait_for_inclusion=True,
            )

            if not result.is_success:
                raise ChainError.from_error(result.error_message)

        except Exception as e:
            # 3. Revert the withdrawal if the stake transfer fails.
            try:
                self.force_deposit(
                    amount=amount.rao,
                    address=source_hotkey,
                    owner_address=owner_address,
                    owner_private_key=owner_private_key,
                )

            except Exception as e:
                # When the revert fails, raise a critical error.
                raise CriticalError(f"Failed to revert the withdrawal from the EVM contract: {e}") from e

            # After reverting the withdrawal, raise an error for the stake transfer failure.
            raise SubtensorError(f"Failed to transfer the stake to the destination wallet: {e}") from e

        return amount

    # ============================================================================
    # Contributor-related methods
    # ============================================================================

    def contributor_balance(self, miner_address: str, contributor_address: str) -> int:
        """
        Get the balance of the deposited alpha tokens for the given miner-contributor pair.

        Args:
            miner_address (str): The SS58 address of the miner.
            contributor_address (str): The SS58 address of the contributor.

        Returns:
            int: The balance of the miner-contributor pair in Rao unit.
        """

        if not is_valid_ss58_address(miner_address):
            raise ValueError(f"Invalid miner SS58 address: {miner_address}")

        if not is_valid_ss58_address(contributor_address):
            raise ValueError(f"Invalid contributor SS58 address: {contributor_address}")

        balance = self.contributor_contract.functions.contributorBalance(
            ss58_to_h160(miner_address), ss58_to_h160(contributor_address)
        ).call()
        return balance

    def contributor_miner_total(self, miner_address: str) -> int:
        """
        Get the total collateral amount for a specific miner across all contributors.

        Args:
            miner_address (str): The SS58 address of the miner.

        Returns:
            int: The total collateral amount for the miner in Rao unit.
        """

        if not is_valid_ss58_address(miner_address):
            raise ValueError(f"Invalid miner SS58 address: {miner_address}")

        total = self.contributor_contract.functions.minerTotalCollateral(ss58_to_h160(miner_address)).call()
        return total

    def contributor_miner_slashed(self, miner_address: str) -> int:
        """
        Get the total amount of slashed collateral for a specific miner.

        Args:
            miner_address (str): The SS58 address of the miner.

        Returns:
            int: The total amount of slashed collateral for the miner in Rao unit.
        """

        if not is_valid_ss58_address(miner_address):
            raise ValueError(f"Invalid miner SS58 address: {miner_address}")

        slashed = self.contributor_contract.functions.minerSlashedCollateral(ss58_to_h160(miner_address)).call()
        return slashed

    def contributor_total(self) -> int:
        """
        Get the total amount of collateral in the contributor EVM contract across all miners and contributors.

        Returns:
            int: The total amount of collateral in Rao unit.
        """

        balance = self.contributor_contract.functions.totalCollateral().call()
        return balance

    def contributor_slashed(self) -> int:
        """
        Get the total amount of slashed collateral in the contributor EVM contract.

        Returns:
            int: The total amount of slashed collateral in Rao unit.
        """

        balance = self.contributor_contract.functions.slashedCollateral().call()
        return balance

    def contributor_deposit(
        self,
        extrinsic: GenericExtrinsic,
        source_hotkey: str,
        vault_stake: str,
        vault_wallet: Wallet,
        miner_address: str,
        contributor_address: str,
        owner_address: str,
        owner_private_key: str,
        wallet_password: Optional[str] = None,
        max_backoff: float = 30.0,
        max_retries: int = 3,
    ) -> Balance:
        """
        Submit the extrinsic to the Subtensor network and deposit the alpha tokens into the contributor EVM contract.
        This function should be called on the owner validator side.

        Args:
            extrinsic (GenericExtrinsic): The signed extrinsic for the stake transfer.
            source_hotkey (str): The source miner hotkey to deposit from.
            vault_stake (str): The stake's SS58 address of the vault to deposit the alpha tokens to.
            vault_wallet (Wallet): The wallet of the vault.
            miner_address (str): The SS58 address of the miner to deposit for.
            contributor_address (str): The SS58 address of the contributor.
            owner_address (str): The owner address of the EVM contract.
            owner_private_key (str): The private key of the owner.
            wallet_password (Optional[str]): The password for the source wallet.
            max_backoff (float): The maximum backoff time in seconds for retries. Defaults to 30.0.
            max_retries (int): The maximum number of attempts to retry. Defaults to 3.

        Returns:
            Balance: The amount of alpha tokens deposited.

        CAUTION:
            This method is assumed to be called from a trusted node such as a owner/super validator.
            The owner/super validator should store the private key in a secure location, load and pass it to this method.
            NEVER, NEVER expose the private key to the public!

        IMPORTANT:
            If a critical error occurs, log the error and transfer the stake back to the source address manually!
        """

        # Input validation
        if not is_valid_ss58_address(miner_address):
            raise ValueError(f"Invalid miner SS58 address: {miner_address}")

        if not is_valid_ss58_address(contributor_address):
            raise ValueError(f"Invalid contributor SS58 address: {contributor_address}")

        origin_coldkey = (
            ss58_encode((extrinsic["address"].value))
            if extrinsic["address"].value.startswith("0x") or extrinsic["address"].value.startswith("0X")
            else extrinsic["address"].value
        )

        call = extrinsic["call"]
        module_name = call["call_module"]["name"].value
        function_name = call["call_function"]["name"].value

        if not (module_name == "SubtensorModule" and function_name == "transfer_stake"):
            raise ValueError(
                f"Invalid extrinsic: expected 'SubtensorModule.transfer_stake', got '{module_name}.{function_name}'"
            )

        if isinstance(call_args := extrinsic["call"]["call_args"], dict):
            destination_coldkey = call_args["destination_coldkey"].value
            destination_netuid = call_args["destination_netuid"].value
            origin_hotkey = call_args["hotkey"].value
            origin_netuid = call_args["origin_netuid"].value
        else:
            try:
                call_args = extrinsic.value["call"]["call_args"]  # pyright: ignore[reportOptionalSubscript]
                destination_coldkey = next(arg for arg in call_args if arg["name"] == "destination_coldkey")["value"]
                destination_netuid = next(arg for arg in call_args if arg["name"] == "destination_netuid")["value"]
                origin_hotkey = next(arg for arg in call_args if arg["name"] == "hotkey")["value"]
                origin_netuid = next(arg for arg in call_args if arg["name"] == "origin_netuid")["value"]
            except StopIteration:
                raise ValueError("Invalid extrinsic: missing required call arguments")

        if destination_coldkey != vault_wallet.coldkeypub.ss58_address:
            raise ValueError(
                f"The extrinsic's destination {destination_coldkey} does not match the vault wallet {vault_wallet.coldkeypub.ss58_address}"
            )

        if destination_netuid != self.network.netuid:
            raise ValueError(
                f"The extrinsic's destination netuid {destination_netuid} does not match the network's netuid {self.network.netuid}"
            )

        if origin_hotkey != source_hotkey:
            raise ValueError(
                f"The extrinsic's origin hotkey {origin_hotkey} does not match the source hotkey {source_hotkey}"
            )

        if origin_netuid != self.network.netuid:
            raise ValueError(
                f"The extrinsic's origin netuid {origin_netuid} does not match the network's netuid {self.network.netuid}"
            )

        # 1. Transfer the stake to the vault wallet.
        try:
            result: ExtrinsicReceipt = self.subtensor_api._subtensor.substrate.submit_extrinsic(
                extrinsic,
                wait_for_inclusion=True,
            )

            if result.is_success:
                try:
                    stake_added = self._get_stake_added_amount(result.triggered_events)
                except ValueError:
                    raise CriticalError("A stake has been transferred, but the amount is unknown")
            else:
                raise ChainError.from_error(result.error_message)

        except CriticalError:
            raise
        except Exception as e:
            raise SubtensorError(f"Failed to transfer the stake to the vault wallet: {e}") from e

        # 2. Move the stake to the vault's stake address.
        if origin_hotkey != vault_stake:
            try:
                move_call: GenericCall = self.subtensor_api._subtensor.substrate.compose_call(
                    call_module="SubtensorModule",
                    call_function="move_stake",
                    call_params={
                        "origin_hotkey": origin_hotkey,
                        "origin_netuid": self.network.netuid,
                        "destination_hotkey": vault_stake,
                        "destination_netuid": self.network.netuid,
                        "alpha_amount": stake_added.rao,
                    },
                )

                move_extrinsic: GenericExtrinsic = self.subtensor_api._subtensor.substrate.create_signed_extrinsic(
                    call=move_call,
                    keypair=vault_wallet.get_coldkey(wallet_password) if wallet_password else vault_wallet.coldkey,
                )

                result: ExtrinsicReceipt = self.subtensor_api._subtensor.substrate.submit_extrinsic(
                    move_extrinsic,
                    wait_for_inclusion=True,
                )

                if result.is_success:
                    try:
                        stake_added = self._get_stake_added_amount(result.triggered_events)
                    except ValueError:
                        raise CriticalError("A stake has been transferred and moved, but the amount is unknown")
                else:
                    raise ChainError.from_error(result.error_message)

            except CriticalError:
                raise
            except Exception as e:
                # 3. Revert the stake transfer if the stake move fails.
                try:
                    revert_extrinsic: GenericExtrinsic = self.create_stake_transfer_extrinsic(
                        amount=stake_added.rao,
                        source_stake=origin_hotkey,
                        source_wallet=vault_wallet,
                        dest=origin_coldkey,
                        wallet_password=wallet_password,
                    )

                    result: ExtrinsicReceipt = self.subtensor_api._subtensor.substrate.submit_extrinsic(
                        revert_extrinsic,
                        wait_for_inclusion=True,
                    )

                    if not result.is_success:
                        raise ChainError.from_error(result.error_message)

                except Exception as e:
                    # When the revert fails, raise a critical error.
                    raise CriticalError(f"Failed to revert the stake transfer: {e}") from e

                # After reverting the stake transfer, raise an error for the stake move failure.
                raise SubtensorError(f"Failed to move the stake to the vault's stake address: {e}") from e

        # 4. Deposit the collateral into the contributor EVM contract.
        for i in range(max_retries):
            try:
                tx = self.contributor_contract.functions.depositFor(
                    ss58_to_h160(miner_address), ss58_to_h160(contributor_address), stake_added.rao
                ).build_transaction(
                    {
                        "chainId": self.network.evm_chain_id,
                        "from": owner_address,
                        "nonce": self.web3.eth.get_transaction_count(owner_address, block_identifier="pending"),  # pyright: ignore[reportArgumentType]
                    }
                )

                signed_tx = self.web3.eth.account.sign_transaction(tx, private_key=owner_private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

                if receipt["status"] == 1:
                    break
                else:
                    raise RuntimeError(
                        f"Transaction failed: {tx_hash.hex()}" if tx_hash in dir() else "Transaction failed"
                    )

            except Exception as e:
                if i < max_retries - 1:
                    time.sleep(min(2**i, max_backoff))
                    continue
                else:
                    # 5. Revert the stake transfer if deposit in the contributor EVM fails.
                    try:
                        revert_extrinsic: GenericExtrinsic = self.create_stake_transfer_extrinsic(
                            amount=stake_added.rao,
                            source_stake=vault_stake,
                            source_wallet=vault_wallet,
                            dest=origin_coldkey,
                            wallet_password=wallet_password,
                        )

                        result: ExtrinsicReceipt = self.subtensor_api._subtensor.substrate.submit_extrinsic(
                            revert_extrinsic,
                            wait_for_inclusion=True,
                        )

                        if not result.is_success:
                            raise ChainError.from_error(result.error_message)

                    except Exception as e:
                        # When the revert fails, raise a critical error.
                        raise CriticalError(f"Failed to revert the stake transfer: {e}") from e

                    # After reverting the stake transfer, raise an error for the deposit failure.
                    raise EVMError(f"Failed to deposit into the contributor EVM contract: {e}") from e

        return stake_added

    def contributor_withdraw(
        self,
        amount: int,
        source_coldkey: str,
        source_hotkey: str,
        vault_stake: str,
        vault_wallet: Wallet,
        miner_address: str,
        contributor_address: str,
        owner_address: str,
        owner_private_key: str,
        wallet_password: Optional[str] = None,
        max_backoff: float = 30.0,
        max_retries: int = 3,
    ) -> Balance:
        """
        Submit the extrinsic to the Subtensor network and withdraw the alpha tokens from the contributor EVM contract.
        This function should be called on the owner validator side.

        Args:
            amount (int): The alpha token amount to withdraw in Rao unit.
            source_coldkey (str): The source miner coldkey to withdraw the alpha tokens.
            source_hotkey (str): The source miner hotkey to withdraw the alpha tokens.
            vault_stake (str): The stake's SS58 address of the vault to withdraw the alpha tokens from.
            vault_wallet (Wallet): The wallet of the vault.
            miner_address (str): The SS58 address of the miner to withdraw for.
            contributor_address (str): The SS58 address of the contributor.
            owner_address (str): The owner address of the EVM contract.
            owner_private_key (str): The private key of the owner.
            wallet_password (Optional[str]): The password for the source wallet.
            max_backoff (float): The maximum backoff time in seconds for retries. Defaults to 30.0.
            max_retries (int): The maximum number of attempts to retry. Defaults to 3.

        Returns:
            Balance: The amount of alpha tokens withdrawn.

        CAUTION:
            This method is assumed to be called from a trusted node such as a owner/super validator.
            The owner/super validator should store the private key in a secure location, load and pass it to this method.
            NEVER, NEVER expose the private key to the public!

        IMPORTANT:
            If a critical error occurs, log the error and force deposit the withdrawn amount back to the destination address manually!
        """

        if amount <= 0:
            raise ValueError(f"Amount must be greater than zero: {amount}")

        if not is_valid_ss58_address(source_coldkey):
            raise ValueError(f"Invalid source coldkey SS58 address: {source_coldkey}")

        if not is_valid_ss58_address(source_hotkey):
            raise ValueError(f"Invalid source hotkey SS58 address: {source_hotkey}")

        if not is_valid_ss58_address(vault_stake):
            raise ValueError(f"Invalid vault stake SS58 address: {vault_stake}")

        if not is_valid_ss58_address(miner_address):
            raise ValueError(f"Invalid miner SS58 address: {miner_address}")

        if not is_valid_ss58_address(contributor_address):
            raise ValueError(f"Invalid contributor SS58 address: {contributor_address}")

        amount: Balance = Balance.from_rao(amount, netuid=self.network.netuid)

        if amount > (
            balance := Balance.from_rao(
                self.contributor_balance(miner_address, contributor_address), netuid=self.network.netuid
            )
        ):
            raise ValueError(f"Insufficient balance: {balance}, requested: {amount}")

        # 1. Withdraw the collateral from the contributor EVM contract.
        for i in range(max_retries):
            try:
                tx = self.contributor_contract.functions.withdrawFor(
                    ss58_to_h160(miner_address), ss58_to_h160(contributor_address), amount.rao
                ).build_transaction(
                    {
                        "chainId": self.network.evm_chain_id,
                        "from": owner_address,
                        "nonce": self.web3.eth.get_transaction_count(owner_address, block_identifier="pending"),  # pyright: ignore[reportArgumentType]
                    }
                )

                signed_tx = self.web3.eth.account.sign_transaction(tx, private_key=owner_private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

                if receipt["status"] == 1:
                    break
                else:
                    raise RuntimeError(
                        f"Transaction failed: {tx_hash.hex()}" if tx_hash in dir() else "Transaction failed"
                    )

            except Exception as e:
                if i < max_retries - 1:
                    time.sleep(min(2**i, max_backoff))
                    continue
                else:
                    raise EVMError(f"Failed to withdraw from the contributor EVM contract: {e}") from e

        # 2. Transfer the stake to the source coldkey.
        try:
            transfer_extrinsic: GenericExtrinsic = self.create_stake_transfer_extrinsic(
                amount=amount.rao,
                source_stake=vault_stake,
                source_wallet=vault_wallet,
                dest=source_coldkey,
                wallet_password=wallet_password,
            )

            result: ExtrinsicReceipt = self.subtensor_api._subtensor.substrate.submit_extrinsic(
                transfer_extrinsic,
                wait_for_inclusion=True,
            )

            if not result.is_success:
                raise ChainError.from_error(result.error_message)

        except Exception as e:
            # 3. Revert the withdrawal if the stake transfer fails.
            try:
                self.contributor_force_deposit(
                    amount=amount.rao,
                    miner_address=miner_address,
                    contributor_address=contributor_address,
                    owner_address=owner_address,
                    owner_private_key=owner_private_key,
                )

            except Exception as e:
                # When the revert fails, raise a critical error.
                raise CriticalError(f"Failed to revert the withdrawal from the contributor EVM contract: {e}") from e

            # After reverting the withdrawal, raise an error for the stake transfer failure.
            raise SubtensorError(f"Failed to transfer the stake to the destination wallet: {e}") from e

        return amount

    def contributor_force_deposit(
        self,
        miner_address: str,
        contributor_address: str,
        amount: int,
        owner_address: str,
        owner_private_key: str,
        max_backoff: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        """
        Force deposit the specified amount of alpha tokens into the contributor EVM contract without a stake transfer.
        This function should be called on the owner validator side.

        Args:
            miner_address (str): The SS58 address of the miner to deposit for.
            contributor_address (str): The SS58 address of the contributor.
            amount (int): The amount of alpha tokens to deposit in Rao unit.
            owner_address (str): The owner address of the EVM contract.
            owner_private_key (str): The private key of the owner.
            max_backoff (float): The maximum backoff time in seconds for retries. Defaults to 30.0.
            max_retries (int): The maximum number of attempts to retry. Defaults to 3.

        Returns:
            None

        CAUTION:
            This method is assumed to be called from a trusted node such as a owner/super validator.
            The owner/super validator should store the private key in a secure location, load and pass it to this method.
            NEVER, NEVER expose the private key to the public!
        """

        if not is_valid_ss58_address(miner_address):
            raise ValueError(f"Invalid miner SS58 address: {miner_address}")

        if not is_valid_ss58_address(contributor_address):
            raise ValueError(f"Invalid contributor SS58 address: {contributor_address}")

        if amount <= 0:
            raise ValueError(f"Amount must be greater than zero: {amount}")

        for i in range(max_retries):
            try:
                tx = self.contributor_contract.functions.depositFor(
                    ss58_to_h160(miner_address), ss58_to_h160(contributor_address), amount
                ).build_transaction(
                    {
                        "chainId": self.network.evm_chain_id,
                        "from": owner_address,
                        "nonce": self.web3.eth.get_transaction_count(owner_address, block_identifier="pending"),  # pyright: ignore[reportArgumentType]
                    }
                )

                signed_tx = self.web3.eth.account.sign_transaction(tx, private_key=owner_private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

                if receipt["status"] == 1:
                    break
                else:
                    raise RuntimeError(
                        f"Transaction failed: {tx_hash.hex()}" if tx_hash in dir() else "Transaction failed"
                    )

            except Exception as e:
                if i < max_retries - 1:
                    time.sleep(min(2**i, max_backoff))
                    continue
                else:
                    raise EVMError(f"Failed to force deposit for miner-contributor pair: {e}") from e

    def contributor_force_withdraw(
        self,
        miner_address: str,
        contributor_address: str,
        amount: int,
        owner_address: str,
        owner_private_key: str,
        max_backoff: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        """
        Force withdraw the specified amount of alpha tokens from the contributor EVM contract without a stake transfer.
        This function should be called on the owner validator side.

        Args:
            miner_address (str): The SS58 address of the miner to withdraw for.
            contributor_address (str): The SS58 address of the contributor.
            amount (int): The amount of alpha tokens to withdraw in Rao unit.
            owner_address (str): The owner address of the EVM contract.
            owner_private_key (str): The private key of the owner.
            max_backoff (float): The maximum backoff time in seconds for retries. Defaults to 30.0.
            max_retries (int): The maximum number of attempts to retry. Defaults to 3.

        Returns:
            None

        CAUTION:
            This method is assumed to be called from a trusted node such as a owner/super validator.
            The owner/super validator should store the private key in a secure location, load and pass it to this method.
            NEVER, NEVER expose the private key to the public!
        """

        if not is_valid_ss58_address(miner_address):
            raise ValueError(f"Invalid miner SS58 address: {miner_address}")

        if not is_valid_ss58_address(contributor_address):
            raise ValueError(f"Invalid contributor SS58 address: {contributor_address}")

        if amount <= 0:
            raise ValueError(f"Amount must be greater than zero: {amount}")

        for i in range(max_retries):
            try:
                tx = self.contributor_contract.functions.withdrawFor(
                    ss58_to_h160(miner_address), ss58_to_h160(contributor_address), amount
                ).build_transaction(
                    {
                        "chainId": self.network.evm_chain_id,
                        "from": owner_address,
                        "nonce": self.web3.eth.get_transaction_count(owner_address, block_identifier="pending"),  # pyright: ignore[reportArgumentType]
                    }
                )

                signed_tx = self.web3.eth.account.sign_transaction(tx, private_key=owner_private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

                if receipt["status"] == 1:
                    break
                else:
                    raise RuntimeError(
                        f"Transaction failed: {tx_hash.hex()}" if tx_hash in dir() else "Transaction failed"
                    )

            except Exception as e:
                if i < max_retries - 1:
                    time.sleep(min(2**i, max_backoff))
                    continue
                else:
                    raise EVMError(f"Failed to force withdraw for miner-contributor pair: {e}") from e

    def contributor_slash(
        self,
        miner_address: str,
        contributor_address: str,
        amount: int,  # pyright: ignore[reportRedeclaration]
        owner_address: str,
        owner_private_key: str,
        max_backoff: float = 30.0,
        max_retries: int = 3,
    ) -> Balance:
        """
        Slash the specified amount of alpha tokens from the contributor EVM contract.
        This function should be called on the owner validator side.

        Args:
            miner_address (str): The SS58 address of the miner.
            contributor_address (str): The SS58 address of the contributor to slash from.
            amount (int): The amount of alpha tokens to slash in Rao unit.
            owner_address (str): The owner address of the EVM contract.
            owner_private_key (str): The private key of the owner.
            max_backoff (float): The maximum backoff time in seconds for retries. Defaults to 30.0.
            max_retries (int): The maximum number of attempts to retry. Defaults to 3.

        Returns:
            Balance: The amount of alpha tokens slashed.

        CAUTION:
            This method is assumed to be called from a trusted node such as a owner/super validator.
            The owner/super validator should store the private key in a secure location, load and pass it to this method.
            NEVER, NEVER expose the private key to the public!
        """

        if not is_valid_ss58_address(miner_address):
            raise ValueError(f"Invalid miner SS58 address: {miner_address}")

        if not is_valid_ss58_address(contributor_address):
            raise ValueError(f"Invalid contributor SS58 address: {contributor_address}")

        if amount <= 0:
            raise ValueError(f"Amount must be greater than zero: {amount}")

        amount: Balance = Balance.from_rao(amount, netuid=self.network.netuid)

        if amount > (
            balance := Balance.from_rao(
                self.contributor_balance(miner_address, contributor_address), netuid=self.network.netuid
            )
        ):
            raise ValueError(f"Insufficient balance: {balance}, requested: {amount}")

        for i in range(max_retries):
            try:
                tx = self.contributor_contract.functions.slashFromContributor(
                    ss58_to_h160(miner_address), ss58_to_h160(contributor_address), amount.rao
                ).build_transaction(
                    {
                        "chainId": self.network.evm_chain_id,
                        "from": owner_address,
                        "nonce": self.web3.eth.get_transaction_count(owner_address, block_identifier="pending"),  # pyright: ignore[reportArgumentType]
                    }
                )

                signed_tx = self.web3.eth.account.sign_transaction(tx, private_key=owner_private_key)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

                if receipt["status"] == 1:
                    break
                else:
                    raise RuntimeError(
                        f"Transaction failed: {tx_hash.hex()}" if tx_hash in dir() else "Transaction failed"
                    )

            except Exception as e:
                if i < max_retries - 1:
                    time.sleep(min(2**i, max_backoff))
                    continue
                else:
                    raise EVMError(f"Failed to slash from contributor: {e}") from e

        return amount
