import binascii

import bdkpython as bdk

from bitcoin_qr_tools.data import (
    Data,
    DataType,
    DecodingException,
    InconsistentDescriptors,
    SignerInfo,
)
from bitcoin_qr_tools.multipath_descriptor import MultipathDescriptor
from bitcoin_qr_tools.unified_decoder import UnifiedDecoder
from bitcoin_qr_tools.unified_encoder import QrExportTypes, UnifiedEncoder


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
    meta_data_handler = UnifiedDecoder(bdk.Network.REGTEST)
    meta_data_handler.add(s)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.Descriptor
    assert (
        data.data_as_string()
        == "wpkh([7d315cd9/84'/1'/0']tpubDCUCSorYswSAurXv7ZcwfkPR8ms2fmxkEW7LFHuLs85wsCngaNAEVFkAvZSabsnz2VH6NvH4uFd4tZ8J3PSaVaxchE8QCd9wxak5Sugnd9p)#ca2wu8zu"
    )


def test_descriptor_master_xpub():
    # test descriptor
    s = "wpkh([a42c6dd3]tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)#h6kd9udr"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.Descriptor
    assert isinstance(data.data, bdk.Descriptor)
    assert data.data.as_string_private() == s

    # sparrow format for root keys (created by other wallets)
    # bdk.Descriptor cannot handle that but  MultipathDescriptor can
    s = "wpkh([a42c6dd3/m]tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)#lrp3pclf"
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
    meta_data_handler = UnifiedDecoder(bdk.Network.REGTEST)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.MultiPathDescriptor, "Wrong type"
    # bdk returns '  instead of h  (which sparrrow does), so the checksum is different
    assert (
        data.data_as_string()
        == "wsh(sortedmulti(2,[829074ff/48'/1'/0'/2']tpubDDx9arPwEvHGnnkKN1YJXFE4W6JZXyVX9HGjZW75nWe1FCsTYu2k3i7VtCwhGR9zj6UUYnseZUnwL7T6Znru3NmXkcjEQxMqRx7Rxz8rPp4/<0;1>/*,[45f35351/48'/1'/0'/2']tpubDEY3tNWvDs8J6xAmwoirxgff61gPN1V6U5numeb6xjvZRB883NPPpRYHt2A6fUE3YyzDLezFfuosBdXsdXJhJUcpqYWF9EEBmWqG3rG8sdy/<0;1>/*,[d5b43540/48'/1'/0'/2']tpubDFnCcKU3iUF4sPeQC68r2ewDaBB7TvLmQBTs12hnNS8nu6CPjZPmzapp7Woz6bkFuLfSjSpg6gacheKBaWBhDnEbEpKtCnVFdQnfhYGkPQF/<0;1>/*))#2jxldwxn"
    )

    # mainnet

    # 2 descriptors in 2 lines  (coldcard style)
    parts = [
        """wsh(sortedmulti(2,[b4b8e8de/48h/0h/0h/2h]xpub6DfgZZfpDv5JRrigvK9ce264NmRofrevrcmx1N5Y2yA9yPBQ7iSu2bmxVcW6yXT4g7GhaTe97nWTQifHLzksEWDC7va8dV5ygSGRqzDsUyW/<0;1>/*,[829074ff/48h/0h/0h/2h]xpub6F7kX4BXQmadkhCEFfyfAP9xKH4KPPVvetJWuvTDa5DQQdbsMHhiV9sEnXFvA6iBrXPTHekngbRPwBniUHxCBnbt6HutPKgMwcytd4pjunM/<0;1>/*,[c40fbbb2/48h/0h/0h/2h]xpub6ESDx8itWPF2Evgg5WTrBJwXoz3KFAbrdFemct7452QMyXa9G2NKsyNPmi2HPCzAPDop44wGPYVGHBBAZ92o24H6aENRTgzhB9g7mVYfHWr/<0;1>/*))#5rd0djqx"""
    ]
    meta_data_handler = UnifiedDecoder(bdk.Network.BITCOIN)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.MultiPathDescriptor, "Wrong type"
    # bdk returns '  instead of h  (which sparrrow does), so the checksum is different
    assert (
        data.data_as_string()
        == "wsh(sortedmulti(2,[b4b8e8de/48'/0'/0'/2']xpub6DfgZZfpDv5JRrigvK9ce264NmRofrevrcmx1N5Y2yA9yPBQ7iSu2bmxVcW6yXT4g7GhaTe97nWTQifHLzksEWDC7va8dV5ygSGRqzDsUyW/<0;1>/*,[c40fbbb2/48'/0'/0'/2']xpub6ESDx8itWPF2Evgg5WTrBJwXoz3KFAbrdFemct7452QMyXa9G2NKsyNPmi2HPCzAPDop44wGPYVGHBBAZ92o24H6aENRTgzhB9g7mVYfHWr/<0;1>/*,[829074ff/48'/0'/0'/2']xpub6F7kX4BXQmadkhCEFfyfAP9xKH4KPPVvetJWuvTDa5DQQdbsMHhiV9sEnXFvA6iBrXPTHekngbRPwBniUHxCBnbt6HutPKgMwcytd4pjunM/<0;1>/*))#hc239s8u"
    )


def test_multipath_descriptor():

    # 2 descriptors in 2 lines  (coldcard style)
    parts = [
        """wpkh([0f056943/84h/1h/0h]tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/0/*)#erexmnep
    wpkh([0f056943/84h/1h/0h]tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/1/*)#ghu8xxfe"""
    ]
    meta_data_handler = UnifiedDecoder(bdk.Network.REGTEST)
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
    meta_data_handler = UnifiedDecoder(bdk.Network.REGTEST)
    exceptionwas_raised = False
    try:
        for part in parts:
            meta_data_handler.add(part)
        assert meta_data_handler.is_complete()
        meta_data_handler.get_complete_data()
    except DecodingException:
        exceptionwas_raised = True
    assert exceptionwas_raised

    # 2 different descriptors (both valid) in 2 lines  (coldcard style)    should trough error
    parts = [
        """wpkh([0f056943/84h/1h/0h]tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/0/*)
    wpkh([7d315cd9/84h/1h/0h]tpubDCUCSorYswSAurXv7ZcwfkPR8ms2fmxkEW7LFHuLs85wsCngaNAEVFkAvZSabsnz2VH6NvH4uFd4tZ8J3PSaVaxchE8QCd9wxak5Sugnd9p/1/*)"""
    ]
    meta_data_handler = UnifiedDecoder(bdk.Network.REGTEST)
    exceptionwas_raised = False
    try:
        for part in parts:
            meta_data_handler.add(part)
        assert meta_data_handler.is_complete()
        meta_data_handler.get_complete_data()
    except InconsistentDescriptors:
        exceptionwas_raised = True
    assert exceptionwas_raised


def test_descriptor_to_qr_fragements():
    # test descriptor
    s = "wpkh([a42c6dd3]tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)#h6kd9udr"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.Descriptor
    assert isinstance(data.data, bdk.Descriptor)
    assert data.data.as_string_private() == s

    ur_fragments = UnifiedEncoder.generate_fragments_for_qr(
        data, qr_export_type=QrExportTypes.ur, max_qr_size=100
    )
    assert ur_fragments == [
        "ur:crypto-output/1-2/lpadaocskicyioataxfmhdfhhdkgtaadmwtaaddlosaowkaxhdclaxeotbflaeneoxfpflweiotkonvthylocxpsjkambbgevodichflmdzowzcntlltaaaahdcxrkrsrdaavylncwfrhhlogahkfnbdmddyoy",
        "ur:crypto-output/2-2/lpaoaocskicyioataxfmhdfhvakpoxwmnnjofhryjsmnbgpmfhynpmcxndcmpdahtaadehoeadaeaoadamtaaddyotadlaaocyoxdwjnteaxaeattaaddyoeadlraewklawkaxaeaycywywfjpwkaebdbtclnl",
    ]


def test_multipath_descriptor_to_qr_fragements():

    # 2 descriptors in 2 lines  (coldcard style)
    s = "wpkh([0f056943/84'/1'/0']tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r/<0;1>/*)#86p2gdxy"

    data = Data.from_str(s, network=bdk.Network.REGTEST)

    ur_fragments = UnifiedEncoder.generate_fragments_for_qr(
        data, qr_export_type=QrExportTypes.ur, max_qr_size=100
    )
    assert ur_fragments == [
        "ur:bytes/1-2/lpadaocsnscytnktlesphdglhdnyktjojeisdehpdyiydyeceneseeeodleteedidlehdidldydihljyjokpidfyfxemimflhshsgufeenengdjteeieiojyidfpfpjkjyieiheeidfxkkisgugojkeejpeogdethgisgthfkogdfwkkkoiabsndvsvw",
        "ur:bytes/2-2/lpaoaocsnscytnktlesphdglgmjpknjpktjsgukojofgesfliskseteohtehgsiyhfkpioflgmjpgufwjejlecgofegrfegsfxknesfdjlgtkoecjsgrjnfljseoiyjsjtjtidguecfeesjpdlfndyfrehfmdldrdtcnetenjoeyioiekskkhpkiwpcl",
    ]
    bbqr_fragments = UnifiedEncoder.generate_fragments_for_qr(data, qr_export_type=QrExportTypes.bbqr)
    assert bbqr_fragments == [
        "B$ZU0100AXA5WCUCGAAABUEP5HA6UZNTJVZRJAO2GJIECHA2CQ63QTCHSKL2SU737LHJTWSKVQP3BAEGJEYAEFWWQCXADKB5Q53OIZ3X77Y3FDCR2OGGVHEXAO3627WI36MLXC3AJGHSLCVMTMEFGFJZRN5ML4RHU6HKT5SCHQYVX2FOA5CTVFS6FSMVGNKGIJ6RVOB7OJWUEZLU73L6WUGR2U2WOBRFCIOOCQJ7QHWWMZMZ5WXMZZ7FB4"
    ]


def test_jade_wallet_export_as_signer_infos():
    s = "23204578706f7274656420627920426c6f636b73747265616d204a6164650a4e616d653a206877693333373463326535356334620a506f6c6963793a2032206f6620330a466f726d61743a2050325753480a44657269766174696f6e3a206d2f3438272f31272f30272f32270a31346339343962343a20747075624444767444534774354a6d677867705270336e795a6a33554c5a76465775553941615336783355776b4e453676614e677a64366f794b594551557a5365765551733273746535517a6e70624e384e74356256625a76724a46704371773955505843746e43757445764577570a44657269766174696f6e3a206d2f3438272f31272f30272f32270a64386366373437353a207470756244454455695563776d6f433932514a326b4750517774696b47714c726a6479556675524d686d356162346e596d67526b6b4b5046396d70324663756e7a4d75397935456132757247554a683474316f375762364b6a4b64647a4a4b634538426f417954574b36756768464b0a44657269766174696f6e3a206d2f3438272f31272f30272f32270a64356234333534303a207470756244466e43634b5533695546347350655143363872326577446142423754764c6d514254733132686e4e53386e753643506a5a506d7a61707037576f7a36626b46754c66536a5370673667616368654b4261574268446e456245704b74436e564664516e666859476b5051460a"
    decoded = binascii.unhexlify(s).decode("utf-8")

    data = Data.from_str(decoded, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.MultisigWalletExport
    assert (
        data.data_as_string()
        == "#  Multisig setup file (created by Bitcoin Safe)\n#\nName: hwi3374c2e55c4b\nPolicy: 2 of 3\nFormat: P2WSH\n\nDerivation: m/48h/1h/0h/2h\n14c949b4: tpubDDvtDSGt5JmgxgpRp3nyZj3ULZvFWuU9AaS6x3UwkNE6vaNgzd6oyKYEQUzSevUQs2ste5QznpbN8Nt5bVbZvrJFpCqw9UPXCtnCutEvEwW\nDerivation: m/48h/1h/0h/2h\nd8cf7475: tpubDEDUiUcwmoC92QJ2kGPQwtikGqLrjdyUfuRMhm5ab4nYmgRkkKPF9mp2FcunzMu9y5Ea2urGUJh4t1o7Wb6KjKddzJKcE8BoAyTWK6ughFK\nDerivation: m/48h/1h/0h/2h\nd5b43540: tpubDFnCcKU3iUF4sPeQC68r2ewDaBB7TvLmQBTs12hnNS8nu6CPjZPmzapp7Woz6bkFuLfSjSpg6gacheKBaWBhDnEbEpKtCnVFdQnfhYGkPQF"
    )


def test_jade_format():
    # jade has a format where they provide an invalid descriptor to conveigh the signer infos
    desc = "wsh([75b600b9/48'/0'/1'/1']xpub6EtDryAmnRPFkJMnrGGnv3zc8CMsqcWkBAeaHw7CXhv8TFxPkA7ZQWjg6epsNMxguzz5BkqfaTMY7yHzY1phCMyJyY9nrouMoSPiBAtH7ei)"
    assert (
        str(SignerInfo.decode_descriptor_as_signer_info(descriptor_str=desc, network=bdk.Network.BITCOIN))
        == "{'fingerprint': '75b600b9', 'key_origin': 'm/48h/0h/1h/1h', 'xpub': 'xpub6EtDryAmnRPFkJMnrGGnv3zc8CMsqcWkBAeaHw7CXhv8TFxPkA7ZQWjg6epsNMxguzz5BkqfaTMY7yHzY1phCMyJyY9nrouMoSPiBAtH7ei', 'derivation_path': None, 'name': 'p2wsh', 'first_address': None}"
    )

    desc = "sh(wsh([75b600b9/48'/0'/1'/1']xpub6EtDryAmnRPFkJMnrGGnv3zc8CMsqcWkBAeaHw7CXhv8TFxPkA7ZQWjg6epsNMxguzz5BkqfaTMY7yHzY1phCMyJyY9nrouMoSPiBAtH7ei))"
    assert (
        str(SignerInfo.decode_descriptor_as_signer_info(descriptor_str=desc, network=bdk.Network.BITCOIN))
        == "{'fingerprint': '75b600b9', 'key_origin': 'm/48h/0h/1h/1h', 'xpub': 'xpub6EtDryAmnRPFkJMnrGGnv3zc8CMsqcWkBAeaHw7CXhv8TFxPkA7ZQWjg6epsNMxguzz5BkqfaTMY7yHzY1phCMyJyY9nrouMoSPiBAtH7ei', 'derivation_path': None, 'name': 'p2sh-wsh', 'first_address': None}"
    )

    desc = "sh([75b600b9/45']xpub68kgMRTM3H3bz4ZeCVPSWgJvAJQFCqTfRYv24WwzweGpu9494gb1oeJLmPEaFR87fRfyASha9pKL147Zw2ZCA4SoHjEfuiNqKdiMZ5XAoNX)#k7sya4f9"
    assert (
        str(SignerInfo.decode_descriptor_as_signer_info(descriptor_str=desc, network=bdk.Network.BITCOIN))
        == "{'fingerprint': '75b600b9', 'key_origin': 'm/45h', 'xpub': 'xpub68kgMRTM3H3bz4ZeCVPSWgJvAJQFCqTfRYv24WwzweGpu9494gb1oeJLmPEaFR87fRfyASha9pKL147Zw2ZCA4SoHjEfuiNqKdiMZ5XAoNX', 'derivation_path': None, 'name': 'p2sh', 'first_address': None}"
    )


def test_sparrow_descriptor_qr_export():
    s = "pkh([ff9f466a/44'/1'/0']tpubDDgB8TAzEbPhcj26514bW3efj4F5x9Xni2FiahV9iSnxdr8sjBQr378L5ke1KXMbadBYw5aAUxAKP33j8LD4y1ZRY6cSySfUN6cu832cXiM)#hl2ce2je"

    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.Descriptor
    assert (
        data.data_as_string()
        == "pkh([ff9f466a/44'/1'/0']tpubDDgB8TAzEbPhcj26514bW3efj4F5x9Xni2FiahV9iSnxdr8sjBQr378L5ke1KXMbadBYw5aAUxAKP33j8LD4y1ZRY6cSySfUN6cu832cXiM)#hl2ce2je"
    )
