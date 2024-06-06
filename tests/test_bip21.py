import bdkpython as bdk

from bitcoin_qr_tools.data import Data, DataType, DecodingException, is_bitcoin_address

# random addresses from mainnet blockchain
TEST_ADDRESSES = [
    "1H8ANdafjpqYntniT3Ddxh4xPBMCSz33pj",
    "3QKAn2B1uDquujLZnoynVoq1M9uac66Ysr",
    "bc1qfjlcqgj9v2tzzfeane5rg9ja23zxur5wg6v0d9",
    "bc1pen855m5pndh8qcqrgjahtg4asqdahur0q5t5r5xhwgmq3zfne7gsctxzpn",
]


def test_address():
    # test descriptor
    for s in TEST_ADDRESSES:
        data = Data.from_str(s, network=bdk.Network.BITCOIN)
        assert data.data_type == DataType.Bip21
        assert data.data == {"address": s}

        # test it is not a bitcoin address for regtest
        assert not is_bitcoin_address(s, bdk.Network.REGTEST)

    # test that it is only valid for this network
    for s in TEST_ADDRESSES:
        exception_raised = False
        try:
            data = Data.from_str(s, network=bdk.Network.REGTEST)
        except DecodingException:
            exception_raised = True

        assert exception_raised


def test_bip21():
    # test descriptor
    for address in TEST_ADDRESSES:
        s = f"bitcoin:{address}?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz"
        data = Data.from_str(s, network=bdk.Network.BITCOIN)
        assert data.data_type == DataType.Bip21
        assert data.data == {
            "address": address,
            "amount": 5000000000,
            "label": "Luke-Jr",
            "memo": "Donation for project xyz",
            "message": "Donation for project xyz",
        }

    # test descriptor
    for address in TEST_ADDRESSES:
        s = f"bitcoin:{address}?label=Luke-Jr"
        data = Data.from_str(s, network=bdk.Network.BITCOIN)
        assert data.data_type == DataType.Bip21
        assert data.data == {
            "address": address,
            "label": "Luke-Jr",
        }

    # test that it is only valid for this network
    for address in TEST_ADDRESSES:
        exception_raised = False
        try:

            s = f"bitcoin:{address}?label=Luke-Jr"
            data = Data.from_str(s, network=bdk.Network.REGTEST)

        except DecodingException:
            exception_raised = True

        assert exception_raised
