import bdkpython as bdk

from bitcoin_qr_tools.data import (
    Data,
    DataType,
    DecodingException,
    SignerInfo,
    WrongNetwork,
)
from bitcoin_qr_tools.unified_decoder import UnifiedDecoder


def test_SignerInfo():

    # test SignerInfo
    s = "[a42c6dd3/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.SignerInfo
    assert data.data == SignerInfo(
        **{
            "xpub": "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks",
            "fingerprint": "a42c6dd3",
            "key_origin": "m/84h/1h/0h",
        }
    )

    # test SignerInfo with h instead of '
    s = "[a42c6dd3/84h/1h/0h]tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.SignerInfo
    assert data.data == SignerInfo(
        **{
            "xpub": "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks",
            "fingerprint": "a42c6dd3",
            "key_origin": "m/84h/1h/0h",
        }
    )

    # test SignerInfo with derivation_path
    s = "[a42c6dd3/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.SignerInfo
    assert data.data == SignerInfo(
        **{
            "xpub": "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks",
            "fingerprint": "a42c6dd3",
            "key_origin": "m/84h/1h/0h",
            "derivation_path": "/0/*",
        }
    )

    # test slip132
    s = "[7cf42c8e/84h/1h/0h]vpub5ZfBcsqfiq4GvTyyYpJW13W9KyZTT1TXNd4bvVk8TZ5ShYh2Bjfm5PyVhcSoLwAr23iRUvYtpza8wmCKPYu8ECKyZPAfwDaFniMjpzACeqJ"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.SignerInfo
    assert data.data == SignerInfo(
        **{
            "xpub": "tpubDDhLkT1BjU6gtrZ4firqd92X12x1KdwakUhLqqb3ZUb6Z2zBmGqyTxxbz4SksFRvdEUwbTFtHR7HQWv4DoaPi79UMfJpnZsTv85SNCfeePi",
            "fingerprint": "7cf42c8e",
            "key_origin": "m/84h/1h/0h",
        }
    )

    # test slip132 multisig (the xpub is at a different derivation path)
    s = "[7cf42c8e/48h/1h/0h/2h]Vpub5kwQ4Q4rGphWbu7SwK9TkPwgPkTKykZZLL22mavN7y9uH7gmQB8doAfx6sJrCtfam33p4vYUrZRdzYp8Ky5ogHB6ioUFA6XFCzM2wkeko6v"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.SignerInfo
    assert data.data.__dict__ == {
        "xpub": "tpubDE5U4jVviWBZ9iXA7ZEpYR8FM1oce2N2Pv16mfVjr7q9WRR2DJva6co8acMLAmhm8kkMJsFMRmaHL8v6rzc81hsvgcVzc3MTSfnrtwYZMMy",
        "fingerprint": "7cf42c8e",
        "key_origin": "m/48h/1h/0h/2h",
        "derivation_path": None,
        "first_address": None,
        "name": None,
    }

    assert data.data == SignerInfo(
        **{
            "xpub": "tpubDE5U4jVviWBZ9iXA7ZEpYR8FM1oce2N2Pv16mfVjr7q9WRR2DJva6co8acMLAmhm8kkMJsFMRmaHL8v6rzc81hsvgcVzc3MTSfnrtwYZMMy",
            "fingerprint": "7cf42c8e",
            "key_origin": "m/48'/1'/0'/2'",
        }
    )

    # cobo
    s = """{"xfp":"7cf42c8e","xpub":"tpubDE5U4jVviWBZ9iXA7ZEpYR8FM1oce2N2Pv16mfVjr7q9WRR2DJva6co8acMLAmhm8kkMJsFMRmaHL8v6rzc81hsvgcVzc3MTSfnrtwYZMMy","path":"m\/48'\/0'\/0'\/2'"}"""
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.SignerInfo
    assert data.data == SignerInfo(
        **{
            "fingerprint": "7cf42c8e",
            "key_origin": "m/48'/0'/0'/2'",
            "xpub": "tpubDE5U4jVviWBZ9iXA7ZEpYR8FM1oce2N2Pv16mfVjr7q9WRR2DJva6co8acMLAmhm8kkMJsFMRmaHL8v6rzc81hsvgcVzc3MTSfnrtwYZMMy",
        }
    )
    assert data.data.__dict__ == {
        "fingerprint": "7cf42c8e",
        "key_origin": "m/48h/0h/0h/2h",
        "xpub": "tpubDE5U4jVviWBZ9iXA7ZEpYR8FM1oce2N2Pv16mfVjr7q9WRR2DJva6co8acMLAmhm8kkMJsFMRmaHL8v6rzc81hsvgcVzc3MTSfnrtwYZMMy",
        "derivation_path": None,
        "name": None,
        "first_address": None,
    }


def test_signer_infos():
    #
    parts = [
        """{
        "chain": "XRT",
        "xfp": "0F056943",
        "account": 0,
        "xpub": "tpubD6NzVbkrYhZ4XzL5Dhayo67Gorv1YMS7j8pRUvVMd5odC2LBPLAygka9p7748JtSq82FNGPppFEz5xxZUdasBRCqJqXvUHq6xpnsMcYJzeh",
        "bip44": {
            "name": "p2pkh",
            "xfp": "92B53FD2",
            "deriv": "m/44'/1'/0'",
            "xpub": "tpubDCiHGUNYdRRBPNYm7CqeeLwPWfeb2ZT2rPsk4aEW3eUoJM93jbBa7hPpB1T9YKtigmjpxHrB1522kSsTxGm9V6cqKqrp1EDaYaeJZqcirYB",
            "desc": "pkh([0f056943/44h/1h/0h]tpubDCiHGUNYdRRBPNYm7CqeeLwPWfeb2ZT2rPsk4aEW3eUoJM93jbBa7hPpB1T9YKtigmjpxHrB1522kSsTxGm9V6cqKqrp1EDaYaeJZqcirYB/<0;1>/*)#gx9efxnj",
            "first": "mtHSVByP9EYZmB26jASDdPVm19gvpecb5R"
        },
        "bip49": {
            "name": "p2sh-p2wpkh",
            "xfp": "FD3E8548",
            "deriv": "m/49'/1'/0'",
            "xpub": "tpubDCDqt7XXvhAYY9HSwrCXB7BXqYM4RXB8WFtKgtTXGa6u3U6EV1NJJRFTcuTRyhSY5Vreg1LP8aPdyiAPQGrDJLikkHoc7VQg6DA9NtUxHtj",
            "desc": "sh(wpkh([0f056943/49h/1h/0h]tpubDCDqt7XXvhAYY9HSwrCXB7BXqYM4RXB8WFtKgtTXGa6u3U6EV1NJJRFTcuTRyhSY5Vreg1LP8aPdyiAPQGrDJLikkHoc7VQg6DA9NtUxHtj/<0;1>/*))#7trzzmgc",
            "_pub": "upub5DMRSsh6mNaeiTXEzarZLvZezWp4cGhaDHjMz9iineDN8syqep2XHncDKFVtTUXY4fyKp12qDVVwdfq5rKkw2CDf5fy2gEHyh5NoTC6fiwm",
            "first": "2NCAJ5wD4GvmW32GFLVybKPNphNU8UYoEJv"
        },
        "bip84": {
            "name": "p2wpkh",
            "xfp": "AB82D43E",
            "deriv": "m/84'/1'/0'",
            "xpub": "tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r",
            "desc": "wpkh([0f056943/84h/1h/0h]tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*)#sjuyyvve",
            "_pub": "vpub5Y5a91QvDT3yog4bmgbqFo7GPXpRpozogzQeDArSPzsY8SKGHTgjSswhxhGkRonUQ9tyo9ZSQ1ecLKkVUyewWEUJZdwgUQycvG86FV7sdhZ",
            "first": "bcrt1qupyd58ndsh7lut0et0vtrq432jvu9jtdx8fgyv"
        },
        "bip48_1": {
            "name": "p2sh-p2wsh",
            "xfp": "43BD4CE2",
            "deriv": "m/48'/1'/0'/1'",
            "xpub": "tpubDF2rnouQaaYrUEy2JM1YD3RFzew4onawGM4X2Re67gguTf5CbHonBRiFGe3Xjz7DK88dxBFGf2i7K1hef3PM4cFKyUjcbJXddaY9F5tJBoP",
            "desc": "sh(wsh(sortedmulti(M,[0f056943/48'/1'/0'/1']tpubDF2rnouQaaYrUEy2JM1YD3RFzew4onawGM4X2Re67gguTf5CbHonBRiFGe3Xjz7DK88dxBFGf2i7K1hef3PM4cFKyUjcbJXddaY9F5tJBoP/0/*,...)))",
            "_pub": "Upub5T4XUooQzDXL58NCHk8ZCw9BsRSLCtnyHeZEExAq1XdnBFXiXVrHFuvvmh3TnCR7XmKHxkwqdACv68z7QKT1vwru9L1SZSsw8B2fuBvtSa6"
        },
        "bip48_2": {
            "name": "p2wsh",
            "xfp": "B5EE2F16",
            "deriv": "m/48'/1'/0'/2'",
            "xpub": "tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP",
            "desc": "wsh(sortedmulti(M,[0f056943/48'/1'/0'/2']tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP/0/*,...))",
            "_pub": "Vpub5mtnnUUL8u4oyRf5d2NZJqDypgmpx8FontedpqxNyjXTi6fLp8fmpp2wedS6UyuNpDgLDoVH23c6rYpFSEfB9jhdbD8gek2stjxhwJeE1Eq"
        },
        "bip45": {
            "name": "p2sh",
            "xfp": "9222584E",
            "deriv": "m/45'",
            "xpub": "tpubD8NXmKsmWp3a3DXhbihAYbYLGaRNVdTnr6JoSxxfXYQcmwVtW2hv8QoDwng6JtEonmJoL3cNEwfd2cLXMpGezwZ2vL2dQ7259bueNKj9C8n",
            "desc": "sh(sortedmulti(M,[0f056943/45']tpubD8NXmKsmWp3a3DXhbihAYbYLGaRNVdTnr6JoSxxfXYQcmwVtW2hv8QoDwng6JtEonmJoL3cNEwfd2cLXMpGezwZ2vL2dQ7259bueNKj9C8n/0/*,...))"
        }
    }"""
    ]

    meta_data_handler = UnifiedDecoder(bdk.Network.REGTEST)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.SignerInfos, "Wrong type"
    # bdk returns '  instead of h  (which sparrrow does), so the checksum is different
    assert (
        data.data_as_string()
        == """[SignerInfo({'fingerprint': '0F056943', 'key_origin': 'm/44h/1h/0h', 'xpub': 'tpubDCiHGUNYdRRBPNYm7CqeeLwPWfeb2ZT2rPsk4aEW3eUoJM93jbBa7hPpB1T9YKtigmjpxHrB1522kSsTxGm9V6cqKqrp1EDaYaeJZqcirYB', 'derivation_path': None, 'name': 'p2pkh', 'first_address': 'mtHSVByP9EYZmB26jASDdPVm19gvpecb5R'}), SignerInfo({'fingerprint': '0F056943', 'key_origin': 'm/49h/1h/0h', 'xpub': 'tpubDCDqt7XXvhAYY9HSwrCXB7BXqYM4RXB8WFtKgtTXGa6u3U6EV1NJJRFTcuTRyhSY5Vreg1LP8aPdyiAPQGrDJLikkHoc7VQg6DA9NtUxHtj', 'derivation_path': None, 'name': 'p2sh-p2wpkh', 'first_address': '2NCAJ5wD4GvmW32GFLVybKPNphNU8UYoEJv'}), SignerInfo({'fingerprint': '0F056943', 'key_origin': 'm/84h/1h/0h', 'xpub': 'tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r', 'derivation_path': None, 'name': 'p2wpkh', 'first_address': 'bcrt1qupyd58ndsh7lut0et0vtrq432jvu9jtdx8fgyv'}), SignerInfo({'fingerprint': '0F056943', 'key_origin': 'm/48h/1h/0h/1h', 'xpub': 'tpubDF2rnouQaaYrUEy2JM1YD3RFzew4onawGM4X2Re67gguTf5CbHonBRiFGe3Xjz7DK88dxBFGf2i7K1hef3PM4cFKyUjcbJXddaY9F5tJBoP', 'derivation_path': None, 'name': 'p2sh-p2wsh', 'first_address': None}), SignerInfo({'fingerprint': '0F056943', 'key_origin': 'm/48h/1h/0h/2h', 'xpub': 'tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP', 'derivation_path': None, 'name': 'p2wsh', 'first_address': None}), SignerInfo({'fingerprint': '0F056943', 'key_origin': 'm/45h', 'xpub': 'tpubD8NXmKsmWp3a3DXhbihAYbYLGaRNVdTnr6JoSxxfXYQcmwVtW2hv8QoDwng6JtEonmJoL3cNEwfd2cLXMpGezwZ2vL2dQ7259bueNKj9C8n', 'derivation_path': None, 'name': 'p2sh', 'first_address': None})]"""
    )


def test_wrong_network_SignerInfos():
    # 2 different descriptors (both valid) in 2 lines  (coldcard style)    should trough error
    parts = [
        """{
        "chain": "BTC",
        "xfp": "0F056943",
        "account": 0,
        "xpub": "tpubD6NzVbkrYhZ4XzL5Dhayo67Gorv1YMS7j8pRUvVMd5odC2LBPLAygka9p7748JtSq82FNGPppFEz5xxZUdasBRCqJqXvUHq6xpnsMcYJzeh"
    }"""
    ]
    meta_data_handler = UnifiedDecoder(bdk.Network.REGTEST)
    exceptionwas_raised = False
    try:
        for part in parts:
            meta_data_handler.add(part)
    except WrongNetwork:
        exceptionwas_raised = True
    assert exceptionwas_raised


def test_wrong_json_SignerInfos():
    # 2 different descriptors (both valid) in 2 lines  (coldcard style)    should trough error
    parts = [
        """{
        "chain": "BTC",
        "xfp": "0F056943",
        "account": 0,
        "xpub": "tpubD6NzVbkrYhZ4XzL5Dhayo67Gorv1YMS7j8pRUvVMd5odC2LBPLAygka9p7748JtSq82FNGPppFEz5xxZUdasBRCqJqXvUHq6xpnsMcYJzeh",
    }"""
    ]
    meta_data_handler = UnifiedDecoder(bdk.Network.REGTEST)
    exceptionwas_raised = False
    try:
        for part in parts:
            meta_data_handler.add(part)
    except DecodingException:
        exceptionwas_raised = True
    assert exceptionwas_raised
