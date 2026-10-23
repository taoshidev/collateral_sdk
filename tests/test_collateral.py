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
