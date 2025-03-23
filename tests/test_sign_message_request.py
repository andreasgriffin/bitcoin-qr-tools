import bdkpython as bdk
import pytest

from bitcoin_qr_tools.data import Data, DataType, DecodingException
from bitcoin_qr_tools.sign_message_request import SignMessageRequest


def test_SignMessageRequest():

    # working
    s = '{"msg":"test message", "subpath": "m/84h/0h/0h/0/10","addr_fmt": "p2wpkh"}'
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.SignMessageRequest
    assert data.data == SignMessageRequest(
        **{"msg": "test message", "subpath": "m/84h/0h/0h/0/10", "addr_fmt": "p2wpkh"}
    )

    # wrong_key
    s = '{"wrong_key":"test message", "subpath": "m/84h/0h/0h/0/10","addr_fmt": "p2wpkh"}'
    with pytest.raises(DecodingException) as exc_info:
        data = Data.from_str(s, network=bdk.Network.REGTEST)

    # missing key
    s = '{ "subpath": "m/84h/0h/0h/0/10","addr_fmt": "p2wpkh"}'
    with pytest.raises(DecodingException) as exc_info:
        data = Data.from_str(s, network=bdk.Network.REGTEST)

    # not json
    s = ' "subpath": "m/84h/0h/0h/0/10","addr_fmt": "p2wpkh"}'
    with pytest.raises(DecodingException) as exc_info:
        data = Data.from_str(s, network=bdk.Network.REGTEST)
