from bitcoin_qrreader.bitcoin_qr import *
from bitcoin_qrreader.multipath_descriptor import *


def test_labels_bip329():
    parts = [
        """{ "type": "tx", "ref": "f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd", "label": "Transaction", "origin": "wpkh([d34db33f/84'/0'/0'])" }
{ "type": "addr", "ref": "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c", "label": "Address" }
{ "type": "pubkey", "ref": "0283409659355b6d1cc3c32decd5d561abaac86c37a353b52895a5e6c196d6f448", "label": "Public Key" }
{ "type": "input", "ref": "f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd:0", "label": "Input" }
{ "type": "output", "ref": "f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd:1", "label": "Output" , "spendable" : "false" }
{ "type": "xpub", "ref": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", "label": "Extended Public Key" }
{ "type": "tx", "ref": "f546156d9044844e02b181026a1a407abfca62e7ea1159f87bbeaa77b4286c74", "label": "Account #1 Transaction", "origin": "wpkh([d34db33f/84'/0'/1'])" }




"""
    ]
    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.LabelsBip329, "Wrong type"
    # bdk returns '  instead of h  (which sparrrow does), so the checksum is different
    assert data.data_as_string() == parts[0].strip()


def test_labels_bip329_single_line():
    parts = [
        """{ "type": "tx", "ref": "f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd", "label": "Transaction"  }"""
    ]
    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.LabelsBip329, "Wrong type"
    # bdk returns '  instead of h  (which sparrrow does), so the checksum is different
    assert data.data_as_string() == parts[0].strip()


def test_labels_missing_key():
    parts = [
        """{ "type": "tx", "ref": "f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd", "label": "Transaction", "origin": "wpkh([d34db33f/84'/0'/0'])" }
        { "type": "addr", "ref": "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c", "label": "Address" }
        { "type": "pubkey", "ref": "0283409659355b6d1cc3c32decd5d561abaac86c37a353b52895a5e6c196d6f448" } 
        """
    ]
    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
    exceptionwas_raised = False
    try:
        for part in parts:
            meta_data_handler.add(part)
    except DecodingException:
        exceptionwas_raised = True
    assert exceptionwas_raised


def test_missing_keywords_in_bip329():
    d = {
        "data": '{"__class__": "Label", "VERSION": "0.0.1", "type": "addr", "ref": "bcrt1qhf8w6h2agu0k6nktcr6tvlfjt2px2ts6tcz09nk5m26et87a7egq90rqc3", "category": "KYC-Exchange", "timestamp": 1710421010.854406}\n{"__class__": "Label", "VERSION": "0.0.1", "type": "addr", "ref": "bcrt1qvml6ssy258ve33jgm8x6c236axtl0wu4pljm2fkj20926muvnarqjfhx7p", "category": "KYC-Exchange", "timestamp": 1710594601.974821}\n{"__class__": "Label", "VERSION": "0.0.1", "type": "tx", "ref": "095544ff305a695d059f5bad721a8436adf012a0f95e176322718a1d0fd1e9c1", "label": "4", "timestamp": 1710676375.340319}',
        "data_type": "LabelsBip329",
    }
    exceptionwas_raised = False
    try:
        data = Data.from_dump(d, network=bdk.Network.REGTEST)
    except DecodingException:
        exceptionwas_raised = True
    assert exceptionwas_raised
