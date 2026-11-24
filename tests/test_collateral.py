from unittest.mock import MagicMock, patch

import pytest

from collateral_sdk.collateral import CollateralManager, Network
from collateral_sdk.errors import EVMError, SubtensorError


def test_tautology():
    assert True is True


def _mock_web3():
    """Patchable stand-in for the Web3 class whose instances share one mocked `eth`."""
    web3_instance = MagicMock()
    web3_instance.eth.get_transaction_count.return_value = 7
    signed_tx = MagicMock()
    signed_tx.hash.hex.return_value = "0xabc"
    web3_instance.eth.account.sign_transaction.return_value = signed_tx
    web3_cls = MagicMock(return_value=web3_instance)
    return web3_cls, web3_instance, signed_tx


def _execute(manager: CollateralManager) -> str:
    return manager._execute_evm_contract_function(
        build_tx_fn=lambda contract: contract.functions.slash("0xminer", 100),
        owner_address="0xowner",
        owner_private_key="key",
        error_message="Failed to slash from the EVM contract",
    )


@patch("collateral_sdk.collateral.time.sleep")
def test_evm_retry_rebroadcasts_the_same_signed_transaction(_sleep):
    # The first broadcast is mined but polling its receipt is rate limited; the
    # rebroadcasts are then rejected because the nonce was already used.
    web3_cls, web3, signed_tx = _mock_web3()
    web3.eth.wait_for_transaction_receipt.side_effect = RuntimeError("429 Client Error: Too Many Requests")
    web3.eth.send_raw_transaction.side_effect = [None, RuntimeError("nonce too low"), RuntimeError("nonce too low")]
    web3.eth.get_transaction_receipt.return_value = {"status": 1}

    with patch("collateral_sdk.collateral.Web3", web3_cls):
        assert _execute(CollateralManager(Network.TESTNET)) == "0xabc"

    web3.eth.account.sign_transaction.assert_called_once()
    web3.eth.get_transaction_count.assert_called_once()
    assert [call.args for call in web3.eth.send_raw_transaction.call_args_list] == [(signed_tx.raw_transaction,)] * 3
    web3.eth.get_transaction_receipt.assert_called_once_with(signed_tx.hash)


@patch("collateral_sdk.collateral.time.sleep")
def test_evm_retry_raises_when_transaction_never_mined(_sleep):
    web3_cls, web3, _ = _mock_web3()
    web3.eth.wait_for_transaction_receipt.side_effect = RuntimeError("429 Client Error: Too Many Requests")
    web3.eth.get_transaction_receipt.side_effect = RuntimeError("not found")

    with patch("collateral_sdk.collateral.Web3", web3_cls):
        with pytest.raises(EVMError, match="Failed to slash from the EVM contract"):
            _execute(CollateralManager(Network.TESTNET))

    web3.eth.account.sign_transaction.assert_called_once()
    assert web3.eth.send_raw_transaction.call_count == 3


@patch("collateral_sdk.collateral.time.sleep")
def test_evm_build_failure_is_retried_before_broadcast(_sleep):
    web3_cls, web3, _ = _mock_web3()
    web3.eth.get_transaction_count.side_effect = [RuntimeError("429 Client Error: Too Many Requests"), 7]
    web3.eth.wait_for_transaction_receipt.return_value = {"status": 1}

    with patch("collateral_sdk.collateral.Web3", web3_cls):
        assert _execute(CollateralManager(Network.TESTNET)) == "0xabc"

    web3.eth.account.sign_transaction.assert_called_once()
    web3.eth.send_raw_transaction.assert_called_once()


@patch("collateral_sdk.collateral.time.sleep")
def test_evm_reverted_transaction_is_not_retried(_sleep):
    web3_cls, web3, _ = _mock_web3()
    web3.eth.wait_for_transaction_receipt.return_value = {"status": 0}

    with patch("collateral_sdk.collateral.Web3", web3_cls):
        with pytest.raises(RuntimeError, match="Transaction failed"):
            _execute(CollateralManager(Network.TESTNET))

    web3.eth.send_raw_transaction.assert_called_once()


@patch("collateral_sdk.collateral.time.sleep")
def test_extrinsic_retry_resubmits_the_same_extrinsic(_sleep):
    manager = CollateralManager(Network.TESTNET)
    manager._subtensor_api = MagicMock()
    submit = manager._subtensor_api.inner_subtensor.substrate.submit_extrinsic
    submit.side_effect = [RuntimeError("429 Client Error: Too Many Requests"), MagicMock(is_success=True)]
    extrinsic = MagicMock()
    create_extrinsic_fn = MagicMock(return_value=extrinsic)

    manager._submit_extrinsic_with_retry(create_extrinsic_fn=create_extrinsic_fn, error_message="Failed to burn")

    create_extrinsic_fn.assert_called_once()
    assert [call.args[0] for call in submit.call_args_list] == [extrinsic, extrinsic]


@patch("collateral_sdk.collateral.time.sleep")
def test_extrinsic_creation_failure_is_retried(_sleep):
    manager = CollateralManager(Network.TESTNET)
    manager._subtensor_api = MagicMock()
    submit = manager._subtensor_api.inner_subtensor.substrate.submit_extrinsic
    submit.return_value = MagicMock(is_success=True)
    create_extrinsic_fn = MagicMock(side_effect=[RuntimeError("429 Client Error: Too Many Requests"), MagicMock()])

    manager._submit_extrinsic_with_retry(create_extrinsic_fn=create_extrinsic_fn, error_message="Failed to burn")

    assert create_extrinsic_fn.call_count == 2
    submit.assert_called_once()


@patch("collateral_sdk.collateral.time.sleep")
def test_extrinsic_retry_exhaustion_raises(_sleep):
    manager = CollateralManager(Network.TESTNET)
    manager._subtensor_api = MagicMock()
    manager._subtensor_api.inner_subtensor.substrate.submit_extrinsic.side_effect = RuntimeError("down")

    with pytest.raises(SubtensorError, match="Failed to burn"):
        manager._submit_extrinsic_with_retry(create_extrinsic_fn=MagicMock(), error_message="Failed to burn")


@patch("collateral_sdk.collateral.SubtensorApi")
@patch("collateral_sdk.collateral.Web3")
def test_default_endpoints_are_the_networks(web3_cls, subtensor_api_cls):
    manager = CollateralManager(Network.MAINNET)

    assert manager.evm_endpoint == "https://lite.chain.opentensor.ai"
    assert manager.subtensor_endpoint == "finney"
    web3_cls.assert_not_called()
    manager.subtensor_api
    subtensor_api_cls.assert_called_once_with(network="finney")


@patch("collateral_sdk.collateral.SubtensorApi")
@patch("collateral_sdk.collateral.Web3")
def test_custom_endpoints_are_used(web3_cls, subtensor_api_cls):
    web3_cls.return_value.eth.chain_id = Network.MAINNET.evm_chain_id
    manager = CollateralManager(
        Network.MAINNET, evm_endpoint="http://127.0.0.1:9944", subtensor_endpoint="ws://127.0.0.1:9944"
    )

    web3_cls.HTTPProvider.assert_called_with("http://127.0.0.1:9944")
    assert manager.program_address == Network.MAINNET.evm_program_address
    assert manager.network.netuid == 8
    manager.balance_of("5C4hrfjw9DjXZTzV3MwzrrAr9P1MJhSrvWGWqi1eSuyUpnhM")
    assert web3_cls.HTTPProvider.call_args_list[-1].args == ("http://127.0.0.1:9944",)
    manager.subtensor_api
    subtensor_api_cls.assert_called_once_with(network="ws://127.0.0.1:9944")


@patch("collateral_sdk.collateral.Web3")
def test_custom_evm_endpoint_on_wrong_chain_raises(web3_cls):
    web3_cls.return_value.eth.chain_id = Network.TESTNET.evm_chain_id

    with pytest.raises(ValueError, match="serves chain id 945, expected 964"):
        CollateralManager(Network.MAINNET, evm_endpoint="http://127.0.0.1:9944")


@patch("collateral_sdk.collateral.Web3")
def test_unreachable_custom_evm_endpoint_raises(web3_cls):
    type(web3_cls.return_value.eth).chain_id = property(MagicMock(side_effect=ConnectionError("refused")))

    with pytest.raises(ValueError, match="Could not reach EVM endpoint"):
        CollateralManager(Network.MAINNET, evm_endpoint="http://127.0.0.1:9944")


# --- deposit(): the stake is in the vault before the EVM step, so every EVM failure
# must end in a credit or a revert, never in a raw exception that strands the stake.


class _V:
    def __init__(self, value):
        self.value = value


def _deposit_extrinsic(netuid: int, vault_coldkey: str, hotkey: str):
    call = {
        "call_module": {"name": _V("SubtensorModule")},
        "call_function": {"name": _V("transfer_stake")},
        "call_args": {
            "destination_coldkey": _V(vault_coldkey),
            "destination_netuid": _V(netuid),
            "hotkey": _V(hotkey),
            "origin_netuid": _V(netuid),
        },
    }
    return {"address": _V("5Origin"), "call": call}


def _deposit(manager: CollateralManager):
    vault = MagicMock()
    vault.coldkeypub.ss58_address = "5Vault"
    return manager.deposit(
        extrinsic=_deposit_extrinsic(manager.network.netuid, "5Vault", "5Miner"),  # pyright: ignore[reportArgumentType]
        source_hotkey="5Miner",
        vault_stake="5Miner",  # same hotkey: skip the move step
        vault_wallet=vault,
        owner_address="0xowner",
        owner_private_key="key",
    )


def _deposit_manager():
    from bittensor.utils.balance import Balance

    manager = CollateralManager(Network.TESTNET)
    manager._subtensor_api = MagicMock()
    submit = manager._subtensor_api.inner_subtensor.substrate.submit_extrinsic
    submit.return_value = MagicMock(is_success=True)
    manager._subtensor_api.staking.get_stake.return_value = Balance.from_rao(1000)
    manager._get_stake_added_amount = MagicMock(return_value=Balance.from_rao(1000))  # pyright: ignore[reportAttributeAccessIssue]
    manager.create_stake_transfer_extrinsic = MagicMock(return_value=MagicMock())  # pyright: ignore[reportAttributeAccessIssue]
    return manager, submit


@patch("collateral_sdk.collateral.ss58_to_h160", lambda x: "0xminer")
@patch("collateral_sdk.collateral.time.sleep")
def test_deposit_nonce_429_is_retried_and_credits(_sleep):
    # The observed mainnet failure: a 429 from the EVM RPC while fetching the nonce,
    # after the stake was already in the vault, escaped as a raw error and stranded it.
    manager, submit = _deposit_manager()
    web3_cls, web3, _ = _mock_web3()
    web3.eth.get_transaction_count.side_effect = [RuntimeError("429 Client Error: Too Many Requests"), 7]
    web3.eth.wait_for_transaction_receipt.return_value = {"status": 1}

    with patch("collateral_sdk.collateral.Web3", web3_cls):
        assert _deposit(manager).rao == 1000

    web3.eth.send_raw_transaction.assert_called_once()
    assert submit.call_count == 1  # the stake transfer only, no revert


@patch("collateral_sdk.collateral.ss58_to_h160", lambda x: "0xminer")
@patch("collateral_sdk.collateral.time.sleep")
def test_deposit_build_never_succeeds_reverts_the_stake(_sleep):
    manager, submit = _deposit_manager()
    web3_cls, web3, _ = _mock_web3()
    web3.eth.get_transaction_count.side_effect = RuntimeError("429 Client Error: Too Many Requests")

    with patch("collateral_sdk.collateral.Web3", web3_cls):
        with pytest.raises(EVMError, match="Failed to deposit into the EVM contract"):
            _deposit(manager)

    web3.eth.send_raw_transaction.assert_not_called()
    assert submit.call_count == 2  # stake transfer + revert
    manager.create_stake_transfer_extrinsic.assert_called_once()  # pyright: ignore[reportAttributeAccessIssue]


@patch("collateral_sdk.collateral.ss58_to_h160", lambda x: "0xminer")
@patch("collateral_sdk.collateral.time.sleep")
def test_deposit_receipt_found_on_later_check_credits(_sleep):
    manager, submit = _deposit_manager()
    web3_cls, web3, _ = _mock_web3()
    web3.eth.wait_for_transaction_receipt.side_effect = RuntimeError("429 Client Error: Too Many Requests")
    web3.eth.get_transaction_receipt.side_effect = [RuntimeError("429"), {"status": 1}]

    with patch("collateral_sdk.collateral.Web3", web3_cls):
        assert _deposit(manager).rao == 1000

    assert submit.call_count == 1  # no revert


@patch("collateral_sdk.collateral.ss58_to_h160", lambda x: "0xminer")
@patch("collateral_sdk.collateral.time.sleep")
def test_deposit_mined_but_receipt_unreadable_does_not_revert(_sleep):
    from collateral_sdk.errors import CriticalError

    manager, submit = _deposit_manager()
    web3_cls, web3, _ = _mock_web3()
    web3.eth.wait_for_transaction_receipt.side_effect = RuntimeError("429 Client Error: Too Many Requests")
    web3.eth.get_transaction_receipt.side_effect = RuntimeError("429 Client Error: Too Many Requests")
    web3.eth.get_transaction_count.side_effect = [7, 8]  # pending at sign, then latest: nonce 7 consumed

    with patch("collateral_sdk.collateral.Web3", web3_cls):
        with pytest.raises(CriticalError, match="was mined"):
            _deposit(manager)

    assert submit.call_count == 1  # reverting here could pay the miner twice


@patch("collateral_sdk.collateral.ss58_to_h160", lambda x: "0xminer")
@patch("collateral_sdk.collateral.time.sleep")
def test_deposit_still_pending_does_not_revert(_sleep):
    from collateral_sdk.errors import CriticalError

    manager, submit = _deposit_manager()
    web3_cls, web3, _ = _mock_web3()
    web3.eth.wait_for_transaction_receipt.side_effect = RuntimeError("429 Client Error: Too Many Requests")
    web3.eth.get_transaction_receipt.side_effect = RuntimeError("not found")
    web3.eth.get_transaction_count.side_effect = [7, 7, 8]  # sign; latest not consumed; still in the mempool

    with patch("collateral_sdk.collateral.Web3", web3_cls):
        with pytest.raises(CriticalError, match="still pending"):
            _deposit(manager)

    assert submit.call_count == 1


@patch("collateral_sdk.collateral.ss58_to_h160", lambda x: "0xminer")
@patch("collateral_sdk.collateral.time.sleep")
def test_deposit_not_mined_and_dropped_reverts(_sleep):
    manager, submit = _deposit_manager()
    web3_cls, web3, _ = _mock_web3()
    web3.eth.wait_for_transaction_receipt.side_effect = RuntimeError("429 Client Error: Too Many Requests")
    web3.eth.get_transaction_receipt.side_effect = RuntimeError("not found")
    web3.eth.get_transaction_count.side_effect = [7, 7, 7]  # never mined, not pending

    with patch("collateral_sdk.collateral.Web3", web3_cls):
        with pytest.raises(EVMError, match="Failed to deposit into the EVM contract"):
            _deposit(manager)

    assert submit.call_count == 2  # stake transfer + revert
