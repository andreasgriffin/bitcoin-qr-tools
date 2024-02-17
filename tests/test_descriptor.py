from bitcoin_qrreader.bitcoin_qr import *
from bitcoin_qrreader.multipath_descriptor import *


def test_descriptor():
    # test descriptor
    s = "wpkh([a42c6dd3/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)#p3rdl64r"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.Descriptor
    assert isinstance(data.data, bdk.Descriptor)
    assert data.data.as_string_private() == s

    # test descriptor without hashsum
    s = "wpkh([a42c6dd3/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.Descriptor
    assert isinstance(data.data, bdk.Descriptor)
    assert data.data.as_string_private().startswith(s)

    # test descriptor with h instead of '
    s = "wpkh([a42c6dd3/84h/1h/0h]tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.Descriptor
    assert isinstance(data.data, bdk.Descriptor)

    # descriptor export from sparrow
    # the strange thing is that sparrow shows
    # "wpkh([7d315cd9/84h/1h/0h]tpubDCUCSorYswSAurXv7ZcwfkPR8ms2fmxkEW7LFHuLs85wsCngaNAEVFkAvZSabsnz2VH6NvH4uFd4tZ8J3PSaVaxchE8QCd9wxak5Sugnd9p/<0;1>/*)#3gahv2xk"
    # but the qr code contains "wpkh([7d315cd9/84'/1'/0']tpubDCUCSorYswSAurXv7ZcwfkPR8ms2fmxkEW7LFHuLs85wsCngaNAEVFkAvZSabsnz2VH6NvH4uFd4tZ8J3PSaVaxchE8QCd9wxak5Sugnd9p)#ca2wu8zu"
    s = "UR:CRYPTO-OUTPUT/TAADMWTAADDLOLAOWKAXHDCLAOVDGSDWLDGMAOIEIDECDPKSPABKRSLUSPWPVAPSFZIEPSMUJLBYETIEFZCFVYDYRTAAHDCXGLBKNBPSPETIJNLYATMUSPNTZCHEFXYTFRFGEHVWDIMEOSINLPHTUTKTWPMERPHGAHTAADEHOEADAEAOADAMTAADDYOTADLNCSGHYKADYKAEYKAOCYKIEHHHTAAXAXAYCYFNLRPAGLLGGSMTFR"
    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
    meta_data_handler.add(s)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert isinstance(data.data, bdk.Descriptor)
    print(s), print(data.data.as_string_private())
    assert (
        data.data.as_string_private()
        == "wpkh([7d315cd9/84'/1'/0']tpubDCUCSorYswSAurXv7ZcwfkPR8ms2fmxkEW7LFHuLs85wsCngaNAEVFkAvZSabsnz2VH6NvH4uFd4tZ8J3PSaVaxchE8QCd9wxak5Sugnd9p)#ca2wu8zu"
    )


def test_descriptor_master_xpub():
    # test descriptor
    s = "wpkh([a42c6dd3]tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)#h6kd9udr"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.Descriptor
    assert isinstance(data.data, bdk.Descriptor)
    assert data.data.as_string_private() == s

    # sparrow format for root keys
    # bdk.Descriptor cannot handle that but  MultipathDescriptor can
    s = "wpkh([a42c6dd3/m]tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.MultiPathDescriptor
    assert isinstance(data.data, MultipathDescriptor)
    assert (
        data.data.as_string_private()
        == "wpkh([a42c6dd3]tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/<0;1>/*)#lmk222x0"
    )


def test_multipath_descriptor1():

    # 2 descriptors in 2 lines  (coldcard style)
    parts = [
        """wsh(sortedmulti(2,[45f35351/48h/1h/0h/2h]tpubDEY3tNWvDs8J6xAmwoirxgff61gPN1V6U5numeb6xjvZRB883NPPpRYHt2A6fUE3YyzDLezFfuosBdXsdXJhJUcpqYWF9EEBmWqG3rG8sdy/<0;1>/*,[829074ff/48h/1h/0h/2h]tpubDDx9arPwEvHGnnkKN1YJXFE4W6JZXyVX9HGjZW75nWe1FCsTYu2k3i7VtCwhGR9zj6UUYnseZUnwL7T6Znru3NmXkcjEQxMqRx7Rxz8rPp4/<0;1>/*,[d5b43540/48h/1h/0h/2h]tpubDFnCcKU3iUF4sPeQC68r2ewDaBB7TvLmQBTs12hnNS8nu6CPjZPmzapp7Woz6bkFuLfSjSpg6gacheKBaWBhDnEbEpKtCnVFdQnfhYGkPQF/<0;1>/*))#54uq36v8"""
    ]
    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.MultiPathDescriptor, "Wrong type"
    # bdk returns '  instead of h  (which sparrrow does), so the checksum is different
    assert (
        data.data_as_string()
        == "wsh(sortedmulti(2,[45f35351/48'/1'/0'/2']tpubDEY3tNWvDs8J6xAmwoirxgff61gPN1V6U5numeb6xjvZRB883NPPpRYHt2A6fUE3YyzDLezFfuosBdXsdXJhJUcpqYWF9EEBmWqG3rG8sdy/<0;1>/*,[829074ff/48'/1'/0'/2']tpubDDx9arPwEvHGnnkKN1YJXFE4W6JZXyVX9HGjZW75nWe1FCsTYu2k3i7VtCwhGR9zj6UUYnseZUnwL7T6Znru3NmXkcjEQxMqRx7Rxz8rPp4/<0;1>/*,[d5b43540/48'/1'/0'/2']tpubDFnCcKU3iUF4sPeQC68r2ewDaBB7TvLmQBTs12hnNS8nu6CPjZPmzapp7Woz6bkFuLfSjSpg6gacheKBaWBhDnEbEpKtCnVFdQnfhYGkPQF/<0;1>/*))#62l47g2m"
    )

    # mainnet

    # 2 descriptors in 2 lines  (coldcard style)
    parts = [
        """wsh(sortedmulti(2,[b4b8e8de/48h/0h/0h/2h]xpub6DfgZZfpDv5JRrigvK9ce264NmRofrevrcmx1N5Y2yA9yPBQ7iSu2bmxVcW6yXT4g7GhaTe97nWTQifHLzksEWDC7va8dV5ygSGRqzDsUyW/<0;1>/*,[829074ff/48h/0h/0h/2h]xpub6F7kX4BXQmadkhCEFfyfAP9xKH4KPPVvetJWuvTDa5DQQdbsMHhiV9sEnXFvA6iBrXPTHekngbRPwBniUHxCBnbt6HutPKgMwcytd4pjunM/<0;1>/*,[c40fbbb2/48h/0h/0h/2h]xpub6ESDx8itWPF2Evgg5WTrBJwXoz3KFAbrdFemct7452QMyXa9G2NKsyNPmi2HPCzAPDop44wGPYVGHBBAZ92o24H6aENRTgzhB9g7mVYfHWr/<0;1>/*))#5rd0djqx"""
    ]
    meta_data_handler = MetaDataHandler(bdk.Network.BITCOIN)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.MultiPathDescriptor, "Wrong type"
    # bdk returns '  instead of h  (which sparrrow does), so the checksum is different
    assert (
        data.data_as_string()
        == "wsh(sortedmulti(2,[b4b8e8de/48'/0'/0'/2']xpub6DfgZZfpDv5JRrigvK9ce264NmRofrevrcmx1N5Y2yA9yPBQ7iSu2bmxVcW6yXT4g7GhaTe97nWTQifHLzksEWDC7va8dV5ygSGRqzDsUyW/<0;1>/*,[829074ff/48'/0'/0'/2']xpub6F7kX4BXQmadkhCEFfyfAP9xKH4KPPVvetJWuvTDa5DQQdbsMHhiV9sEnXFvA6iBrXPTHekngbRPwBniUHxCBnbt6HutPKgMwcytd4pjunM/<0;1>/*,[c40fbbb2/48'/0'/0'/2']xpub6ESDx8itWPF2Evgg5WTrBJwXoz3KFAbrdFemct7452QMyXa9G2NKsyNPmi2HPCzAPDop44wGPYVGHBBAZ92o24H6aENRTgzhB9g7mVYfHWr/<0;1>/*))#6uw6zqx6"
    )


def test_multipath_descriptor():

    # 2 descriptors in 2 lines  (coldcard style)
    parts = [
        """wpkh([0f056943/84h/1h/0h]tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/0/*)#erexmnep
    wpkh([0f056943/84h/1h/0h]tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/1/*)#ghu8xxfe"""
    ]
    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.MultiPathDescriptor, "Wrong type"
    # bdk returns '  instead of h  (which sparrrow does), so the checksum is different
    assert (
        data.data_as_string()
        == "wpkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*)#86p2gdxy"
    )

    # 2 different descriptors (2. invalid) in 2 lines  (coldcard style)    should trough error
    parts = [
        """wpkh([0f056943/84h/1h/0h]tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/0/*)
    wpkh([0f05a943/84h/1h/0h]tpubaaaaGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/1/*)"""
    ]
    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
    exceptionwas_raised = False
    try:
        for part in parts:
            meta_data_handler.add(part)
    except DecodingException:
        exceptionwas_raised = True
    assert exceptionwas_raised

    # 2 different descriptors (both valid) in 2 lines  (coldcard style)    should trough error
    parts = [
        """wpkh([0f056943/84h/1h/0h]tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/0/*)
    wpkh([7d315cd9/84h/1h/0h]tpubDCUCSorYswSAurXv7ZcwfkPR8ms2fmxkEW7LFHuLs85wsCngaNAEVFkAvZSabsnz2VH6NvH4uFd4tZ8J3PSaVaxchE8QCd9wxak5Sugnd9p/1/*)"""
    ]
    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
    exceptionwas_raised = False
    try:
        for part in parts:
            meta_data_handler.add(part)
    except InconsistentDescriptors:
        exceptionwas_raised = True
    assert exceptionwas_raised
