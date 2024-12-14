from typing import List

import bdkpython as bdk
from hwilib.descriptor import parse_descriptor

from bitcoin_qr_tools.data import Data, DataType
from bitcoin_qr_tools.signer_info import SignerInfo
from bitcoin_qr_tools.unified_decoder import UnifiedDecoder
from bitcoin_qr_tools.ur_tools import URTools
from bitcoin_qr_tools.urtypes.crypto import Account as UR_ACCOUNT
from bitcoin_qr_tools.urtypes.crypto import Output as UR_OUTPUT

####  mainnet


def test_ur_binary_output_mainnet():

    cbor = bytes.fromhex(
        "d90194d9012fa702f4035821033b2eac794178b1255ba99937e9f09e61fb877d8e69fd26473c01007e739691570458204d64738b721cabbdd38cab2660109d415db9d28e9914a221ad6f8f3132e1db2405d90131a20100020006d90130a301861854f500f500f5021a0439f926030307d90130a2018400f480f40300081a4f903e6b"
    )
    output = UR_OUTPUT.from_cbor(cbor)

    descriptor = URTools.decode_output_as_descriptor(output, network=bdk.Network.BITCOIN)
    assert (
        descriptor.data_as_string()
        == "wpkh([0439f926/84'/0'/0']xpub6CEgqLoi7LDrHbhDUXePVGwqxNaiLLcwusnzxTCULc7X337quHv1TamzNBXqNMtmwKuQKHEBquk8Sj8CjUAqehCR7MrqDsQdyYADKsjuxA8/0/*)#uryy2xmy"
    )

    signer_info = SignerInfo.decode_descriptor_as_signer_info(
        output.descriptor(), network=bdk.Network.BITCOIN
    )
    assert (
        Data(signer_info, data_type=DataType.SignerInfo, network=bdk.Network.BITCOIN).data_as_string()
        == '{"fingerprint": "0439f926", "key_origin": "m/84h/0h/0h", "xpub": "xpub6CEgqLoi7LDrHbhDUXePVGwqxNaiLLcwusnzxTCULc7X337quHv1TamzNBXqNMtmwKuQKHEBquk8Sj8CjUAqehCR7MrqDsQdyYADKsjuxA8", "derivation_path": "/0/*", "name": "p2wpkh", "first_address": null}'
    )


def test_ur_binary_account_mainnet():

    cbor = b"\xa2\x01\x1a\x049\xf9&\x02\x84\xd9\x01\x94\xd9\x01/\xa7\x02\xf4\x03X!\x03;.\xacyAx\xb1%[\xa9\x997\xe9\xf0\x9ea\xfb\x87}\x8ei\xfd&G<\x01\x00~s\x96\x91W\x04X Mds\x8br\x1c\xab\xbd\xd3\x8c\xab&`\x10\x9dA]\xb9\xd2\x8e\x99\x14\xa2!\xado\x8f12\xe1\xdb$\x05\xd9\x011\xa2\x01\x00\x02\x00\x06\xd9\x010\xa3\x01\x86\x18T\xf5\x00\xf5\x00\xf5\x02\x1a\x049\xf9&\x03\x03\x07\xd9\x010\xa2\x01\x84\x00\xf4\x80\xf4\x03\x00\x08\x1aO\x90>k\xd9\x01\x93\xd9\x01/\xa7\x02\xf4\x03X!\x03'\xfc\xb5H\xb3\x7fKS\xec\x04\xa6#\xa6\xef\xe6\xfc\x93\xd8{\x06\x11\xac\xcf\xb42NIn\xe8\x15\xf4x\x04X ^\x9e\x04\x00\xe8O|\xc4*i\xe9\x02u\xfc\x86\xb89Z\xc7I\xa1}\x98\xef2w3\xed\xad\x1b\xb9\xd8\x05\xd9\x011\xa2\x01\x00\x02\x00\x06\xd9\x010\xa3\x01\x86\x18,\xf5\x00\xf5\x00\xf5\x02\x1a\x049\xf9&\x03\x03\x07\xd9\x010\xa2\x01\x84\x00\xf4\x80\xf4\x03\x00\x08\x1a\x0f\x8b\x07\x95\xd9\x01\x90\xd9\x01\x94\xd9\x01/\xa7\x02\xf4\x03X!\x02T\x81\xe7\n2\xdc\x9c\x04#\xf4\x92+\xa0h\x8e\xffE!\x89\x01\x12\xc6\x8aD\x1f\x05\xf2\x11d\x0e\x8b\x01\x04X q\xcet\x0c\xda\x83z\xbe\xecm\xfb\x83\xaa\xb8\x11\n+\xae~w\xa0\x03uu'W\xea8EQ\xf7\xa3\x05\xd9\x011\xa2\x01\x00\x02\x00\x06\xd9\x010\xa3\x01\x86\x181\xf5\x00\xf5\x00\xf5\x02\x1a\x049\xf9&\x03\x03\x07\xd9\x010\xa2\x01\x84\x00\xf4\x80\xf4\x03\x00\x08\x1ax\x9aV\xff\xd9\x01\x99\xd9\x01/\xa7\x02\xf4\x03X!\x03oR\xc4\x94\x80\xc4fJ\xed\xaf\x0f\xcc\xf5\x18\xd8\xa1\x81N\x7f\x8a\xe4\xb2\xe1c`S\xad\x02\x90:\xb2\xc5\x04X %wv'R\xa1U\xd8\x8d\x95\x8c\xf4>\xfe\xe8h\x94\xb47*\xafe\xe6\xac\\\xfb\x7f{D\xcf\xde-\x05\xd9\x011\xa2\x01\x00\x02\x00\x06\xd9\x010\xa3\x01\x86\x18V\xf5\x00\xf5\x00\xf5\x02\x1a\x049\xf9&\x03\x03\x07\xd9\x010\xa2\x01\x84\x00\xf4\x80\xf4\x03\x00\x08\x1a\xf7o\xe4\xa8"
    source_account = UR_ACCOUNT.from_cbor(cbor)
    signer_infos = URTools.decode_account_as_signer_infos(account=source_account, network=bdk.Network.BITCOIN)
    assert (
        str(signer_infos)
        == "[SignerInfo({'fingerprint': '0439f926', 'key_origin': 'm/84h/0h/0h', 'xpub': 'xpub6CEgqLoi7LDrHbhDUXePVGwqxNaiLLcwusnzxTCULc7X337quHv1TamzNBXqNMtmwKuQKHEBquk8Sj8CjUAqehCR7MrqDsQdyYADKsjuxA8', 'derivation_path': '/0/*', 'name': 'p2wpkh', 'first_address': None}), SignerInfo({'fingerprint': '0439f926', 'key_origin': 'm/44h/0h/0h', 'xpub': 'xpub6BmPsBkcyiMggt5M9RfKZAS6BZw6Vz4rhCbaKBzPF7eP9D92HDqRH5qXK4ZrJNYZhjXKNV3pXm8B2nENQhSdnVMA9kNui2YJuSpyv6be4eD', 'derivation_path': '/0/*', 'name': 'p2pkh', 'first_address': None}), SignerInfo({'fingerprint': '0439f926', 'key_origin': 'm/49h/0h/0h', 'xpub': 'xpub6CYBaMFJiUpP5fuwNxnB7hYS19kgteAWpRw3aasa4nDn13EZiwoJKZRZZJ8NAzZT4teiMwQooYVNYwTfgMu5eJSwHUmv2Zysb2GF5mTKf2d', 'derivation_path': '/0/*', 'name': 'p2sh-p2wpkh', 'first_address': None}), SignerInfo({'fingerprint': '0439f926', 'key_origin': 'm/86h/0h/0h', 'xpub': 'xpub6DUFgM9mxwoMqP525JwVGQnhBtUVT2rXFz9wEdfy8MuZAbUFLWQBJgkmvmVt7gWvYZXoresMFsFvVKc9qSvhFHsBrorb5g9nGPkGy7YJkgT', 'derivation_path': '/0/*', 'name': 'p2tr', 'first_address': None})]"
    )

    # and reverse
    descriptor_names: List[str] = [signer_info.name for signer_info in signer_infos]
    account = URTools.encode_ur_account(signer_infos=signer_infos, descriptor_names=descriptor_names)
    assert source_account.to_cbor() == account.to_cbor()


def test_ur_account_testvector():
    """modified from https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-015-account.md"""

    cbor = bytes.fromhex(
        "a2011a37b5eed40284d90193d9012fa403582103eb3e2863911826374de86c231a4b76f0b89dfa174afb78d7f478199884d9dd320458206456a5df2db0f6d9af72b2a1af4b25f45200ed6fcc29c3440b311d4796b70b5b06d90130a20186182cf500f500f5021a37b5eed4081a99f9cdf7d90190d90194d9012fa403582102c7e4823730f6ee2cf864e2c352060a88e60b51a84e89e4c8c75ec22590ad6b690458209d2f86043276f9251a4a4f577166a5abeb16b6ec61e226b5b8fa11038bfda42d06d90130a201861831f500f500f5021a37b5eed4081aa80f7cdbd90194d9012fa403582103fd433450b6924b4f7efdd5d1ed017d364be95ab2b592dc8bddb3b00c1c24f63f04582072ede7334d5acf91c6fda622c205199c595a31f9218ed30792d301d5ee9e3a8806d90130a201861854f500f500f5021a37b5eed4081a0d5de1d7d90199d9012fa403582102bbb97cf9efa176b738efd6ee1d4d0fa391a973394fbc16e4c5e78e536cd14d2d0458204b4693e1f794206ed1355b838da24949a92b63d02e58910bf3bd3d9c242281e606d90130a201861856f500f500f5021a37b5eed4081acec7070c"
    )
    source_account = UR_ACCOUNT.from_cbor(cbor)
    # corrections to the test vector (the testvector is actually wrong/incomplete!!!)
    for d in source_account.output_descriptors:
        d.crypto_key.origin.depth = len(d.crypto_key.origin.components)
        d.crypto_key.use_info = URTools._use_info(False)
        d.crypto_key.private_key = False

    signer_infos = URTools.decode_account_as_signer_infos(account=source_account, network=bdk.Network.BITCOIN)
    assert (
        str(signer_infos)
        == "[SignerInfo({'fingerprint': '37b5eed4', 'key_origin': 'm/44h/0h/0h', 'xpub': 'xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu', 'derivation_path': None, 'name': 'p2pkh', 'first_address': None}), SignerInfo({'fingerprint': '37b5eed4', 'key_origin': 'm/49h/0h/0h', 'xpub': 'xpub6CtR1iF4dZPkEyXDwVf3HE74tSwXNMcHtBzX4gwz2UnPhJ54Jz5unHx2syYCCDkvVUmsmoYTmcaHXe1wJppvct4GMMaN5XAbRk7yGScRSte', 'derivation_path': None, 'name': 'p2sh-p2wpkh', 'first_address': None}), SignerInfo({'fingerprint': '37b5eed4', 'key_origin': 'm/84h/0h/0h', 'xpub': 'xpub6BkU445MSEBXbPjD3g2c2ch6mn8yy1SXXQUM7EwjgYiq6Wt1NDwDZ45npqWcV8uQC5oi2gHuVukoCoZZyT4HKq8EpotPMqGqxdZRuapCQ23', 'derivation_path': None, 'name': 'p2wpkh', 'first_address': None}), SignerInfo({'fingerprint': '37b5eed4', 'key_origin': 'm/86h/0h/0h', 'xpub': 'xpub6DAvL2L5bgGSpDygSQUDpjwE47saoMk2rSRtYhN7Dma7HvnFLTXNrcSC1AmEN8G2SCD958bUwgc6Bew4sAFa2kqYynF8Rmu6P5jMt2FDPtm', 'derivation_path': None, 'name': 'p2tr', 'first_address': None})]"
    )

    # and reverse
    descriptor_names: List[str] = [signer_info.name for signer_info in signer_infos]
    account = URTools.encode_ur_account(signer_infos=signer_infos, descriptor_names=descriptor_names)
    assert source_account.to_cbor() == account.to_cbor()


def test_ur_account_mainnet():
    parts = [
        "UR:CRYPTO-ACCOUNT/7-3/LPATAXCFAOBBCYBWJOSKJKHDPROEADAEAOAEAMTAADDYOTADLNCSEHYKAEYKAEYKAOCYAAESYTDSAXAXATTAADDYOEADLRAEWKLAWKAXAEAYCYKSNYHFZMTAADNLTAADDLOSAOWKAXHDCLAXJLGMSSMWLASSIYGEWEPEBSSFYKCSTPOYLYGLLBLEVEPRVYIAHNGUPMAOMHFTPRSKAAHDCXDAKTKODIGMOYGOTPLGMDLKWKFMZEVSISMWQZEMDRPEIHVAPSHHZOLBKGFYTKUEDPAHTAADEHOEADAEAOAEAMTAADDYOTADLNCSHFYKAEYKAEYKAOCYAAESYTDSAXAXATTAADDYOEADLRAEWKLAWKAXAEAYCYYLJLVEPDAEAEDRZEJOGS",
        "UR:CRYPTO-ACCOUNT/8-3/LPAYAXCFAOBBCYBWJOSKJKHDPROEADAEAOAEAMTAADDYOTADLNCSEHYKAEYKAEYKAOCYAAESYTDSAXAXATTAADDYOEADLRAEWKLAWKAXAEAYCYKSNYHFZMTAADNLTAADDLOSAOWKAXHDCLAXJLGMSSMWLASSIYGEWEPEBSSFYKCSTPOYLYGLLBLEVEPRVYIAHNGUPMAOMHFTPRSKAAHDCXDAKTKODIGMOYGOTPLGMDLKWKFMZEVSISMWQZEMDRPEIHVAPSHHZOLBKGFYTKUEDPAHTAADEHOEADAEAOAEAMTAADDYOTADLNCSHFYKAEYKAEYKAOCYAAESYTDSAXAXATTAADDYOEADLRAEWKLAWKAXAEAYCYYLJLVEPDAEAEFXKKOLWY",
        "UR:CRYPTO-ACCOUNT/9-3/LPASAXCFAOBBCYBWJOSKJKHDPRWMJLWZBYSNLYCPHTOXLTNEMHTAWLHNUYSWUEIMPACNKOSTPDBBFZCWRSYALRDSEHKOAHNNSRJKSFVTFMONLUPFZTCHVWFSADAOKBKPGWMHIOOSHKOLGOFDLNLULTCEHYRSSOLOMOURFGBWNNFGLRROVODWMKMHOETLDPNDLKEHFTZOTYPEAOGSTPDYEYTPADMTTAATYNOLEYHGAOUEESHFOYLYBGBKSTUELNAECYBTQZDEOTJLHGZEKPLSLOLPBGEYBKPFCEAHZSBDDNNNREIMUTHKQDPDTKHPPYTPKTKKVASNJTUOLBCTWTOEKPHNZCMOJKAMCXTENYSEPYKKVTFMHGVABSSGJNEOLBLALGLSGH",
        "UR:CRYPTO-ACCOUNT/10-3/LPBKAXCFAOBBCYBWJOSKJKHDPRGAJTWZBWSNLTZOHPMWDKNNCMSETPMDUYEOUENEQDESJPZEGYEYFXCSROCLLPCMMUKTLYNNEMWFETVLFMPMMESPIYFPCYVEAENDOSJYHNEMIHGUHTZEJYGRWLTAFXLOUEKGPESALBJOGAURJEHYHHCFIAIDVDCYFGIOSFYAWPIDMSYTFYMDPFLDUOISBGZCKOVTZEGOHGWFWDTNMSGMSNISHEINKNNNJKWLPSPELBWMCSJYHDBEDWRDRDHLONLASBEOFRBGCAAHYABDDPFLQZHTKBHDECPFNLPLPYDPKTLKVETSIMVWLNESWFOYJPRHZTOETTATOXTEJTFPHEKNVTENGTBYHNDMSKEOLBDLJKENVD",
        "UR:CRYPTO-ACCOUNT/11-3/LPBDAXCFAOBBCYBWJOSKJKHDPRGAJTVSBZWKKSAAHDCXHYNNAAAEVSGWKESSDRINWLAOKPZTLNROESHTSTGAOYKIMKWSEYKTEOWEPMCWRHTPAHTAADEHOEADAEAOAEAMTAADDYOTADLNCSDWYKAEYKAEYKAOCYAAESYTDSAXAXATTAADDYOEADLRAEWKLAWKAXAEAYCYBSLUATMDTAADMHTAADMWTAADDLOSAOWKAXHDCLAOGHLYVDBKEYUONSAACNWKMODNNBISMNZMFECLLDADBGSWLEFYCTAHWZBYIEBALUADAAHDCXJSTOJYBNTNLSKNRNWPJNZOLSPKROBYBKDNPLKBKTNBAXKPKPDIHGWDETFEGYYLOTAHTAADEHKGKPHHGU",
    ]

    meta_data_handler = UnifiedDecoder(bdk.Network.BITCOIN)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()

    assert data.data_type == DataType.SignerInfos

    assert [d.__dict__ for d in data.data] == [
        {
            "fingerprint": "0439f926",
            "key_origin": "m/84h/0h/0h",
            "xpub": "xpub6CEgqLoi7LDrHbhDUXePVGwqxNaiLLcwusnzxTCULc7X337quHv1TamzNBXqNMtmwKuQKHEBquk8Sj8CjUAqehCR7MrqDsQdyYADKsjuxA8",
            "derivation_path": "/0/*",
            "name": "p2wpkh",
            "first_address": None,
        },
        {
            "fingerprint": "0439f926",
            "key_origin": "m/44h/0h/0h",
            "xpub": "xpub6BmPsBkcyiMggt5M9RfKZAS6BZw6Vz4rhCbaKBzPF7eP9D92HDqRH5qXK4ZrJNYZhjXKNV3pXm8B2nENQhSdnVMA9kNui2YJuSpyv6be4eD",
            "derivation_path": "/0/*",
            "name": "p2pkh",
            "first_address": None,
        },
        {
            "fingerprint": "0439f926",
            "key_origin": "m/49h/0h/0h",
            "xpub": "xpub6CYBaMFJiUpP5fuwNxnB7hYS19kgteAWpRw3aasa4nDn13EZiwoJKZRZZJ8NAzZT4teiMwQooYVNYwTfgMu5eJSwHUmv2Zysb2GF5mTKf2d",
            "derivation_path": "/0/*",
            "name": "p2sh-p2wpkh",
            "first_address": None,
        },
        {
            "fingerprint": "0439f926",
            "key_origin": "m/86h/0h/0h",
            "xpub": "xpub6DUFgM9mxwoMqP525JwVGQnhBtUVT2rXFz9wEdfy8MuZAbUFLWQBJgkmvmVt7gWvYZXoresMFsFvVKc9qSvhFHsBrorb5g9nGPkGy7YJkgT",
            "derivation_path": "/0/*",
            "name": "p2tr",
            "first_address": None,
        },
    ]


def test_hd_key_conversions():
    ## input
    cbor = bytes.fromhex(
        "d90194d9012fa702f4035821033b2eac794178b1255ba99937e9f09e61fb877d8e69fd26473c01007e739691570458204d64738b721cabbdd38cab2660109d415db9d28e9914a221ad6f8f3132e1db2405d90131a20100020006d90130a301861854f500f500f5021a0439f926030307d90130a2018400f480f40300081a4f903e6b"
    )
    source_output = UR_OUTPUT.from_cbor(cbor)

    ## UR_output --> Descriptor
    descriptor = URTools.decode_output_as_descriptor(source_output, network=bdk.Network.BITCOIN)

    ## Descriptor --> PubkeyProvider
    assert (
        descriptor.data_as_string()
        == "wpkh([0439f926/84'/0'/0']xpub6CEgqLoi7LDrHbhDUXePVGwqxNaiLLcwusnzxTCULc7X337quHv1TamzNBXqNMtmwKuQKHEBquk8Sj8CjUAqehCR7MrqDsQdyYADKsjuxA8/0/*)#uryy2xmy"
    )
    hwi_descriptor = parse_descriptor(descriptor.data_as_string())
    expected_hwi_pubkey = hwi_descriptor.pubkeys[0]

    ## _hd_key_to_pubkey_provider: hdkey --> PubkeyProvider

    source_hdkey = source_output.hd_key()
    provider = URTools._hd_key_to_pubkey_provider(hdkey=source_hdkey)

    # 2 PubkeyProvider are identical
    assert expected_hwi_pubkey.pubkey == provider.pubkey
    assert expected_hwi_pubkey.origin.to_string() == provider.origin.to_string()
    assert expected_hwi_pubkey.deriv_path == provider.deriv_path

    # also test _pubkey_provider_to_hdkey

    hdkey = URTools._pubkey_provider_to_hdkey(expected_hwi_pubkey)
    # URComparator.verbose_compare_hdkeys(source_hdkey, hdkey)
    assert hdkey.to_cbor() == source_hdkey.to_cbor()


####  Regtest


def test_encode_descriptor_single_sig():
    """
    Source of test data: sparrow
    """
    parts = [
        "UR:CRYPTO-OUTPUT/TAADMWTAADDLOSAOWKAXHDCLAOMTCHVSWELUOLPEETWPCYSSDNOTBTGRCAPLIYKGTLBDNYRKIHBAECVWLDFHTONSSWAAHDCXZEHHRFBBROGAFYRLGDCKFXCAMOFRVEPDPEEYWTPDLSLNBYSBAEREFDGWFWGYFWJNAHTAADEHOEADAEAOADAMTAADDYOTADLNCSGHYKADYKAEYKAOCYBSAHINFXAXAXAYCYKBBARHSGASIMGRIHKKJKJYJLJPIHCXEHMEPDAYGE"
    ]

    meta_data_handler = UnifiedDecoder(bdk.Network.REGTEST)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()

    excpected_output_cbor = meta_data_handler.last_used_collector.decoder.result.cbor

    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.SignerInfo

    expected_output = UR_OUTPUT.from_cbor(excpected_output_cbor)
    expected_descriptor_str = "wpkh([0f056943/84'/1'/0']tpubDCx8y86cKonoPyTtj3f9NZLpBYoBNkbAzUdafMHhggjxkhF8Dny2aekWfDafywEMZEQaQjkK9Gxn7aN7usLRUQdYbvDgcnmYRf72khPEouL)#mm3znrc9"
    assert expected_output.descriptor() == expected_descriptor_str

    ## encode_descriptor

    output = URTools.encode_ur_output(expected_descriptor_str, keystore_name="Keystore 1")
    # URComparator.verbose_compare_output(output, expected_output)
    assert output.to_cbor() == expected_output.to_cbor()


def test_encode_descriptor_multi_sig2():
    """
    Source of test data: sparrow
    """
    parts = [
        "UR:CRYPTO-OUTPUT/TAADMETAADMSOEADADAOLFTAADDLOSAOWKAXHDCLAXETVWRPCTOXMYTPPTFPDAHGKBRONNDYAYUOLUHGLKVYGEWZZCNNDKKOOYAXECRPVDAAHDCXRNDTCWIATOTYSKMWDIYNNYROASMULPLFTYNNRTPEWSJKAYDKFZCKHYDKDEBNURFPAHTAADEHOEADAEAOADAMTAADDYOTADLOCSDYYKADYKAEYKAOYKAOCYGHHKWZFRAXAAAYCYNEKGIMOTASIOFWGAGDEOESCXEYTAADDLOSAOWKAXHDCLAXZSFTBEMOMYLNTSOEECFGLGSGWLECPRAXRHVTDYIAONGROXUYAMCNBBSRLRWYWZAXAAHDCXDSCADYDIRKSAHGIYZETIFYDYSFSBHKGMTDCAGEEYBTKOFXRPAAAOJLSTFNPELOFEAHTAADEHOEADAEAOADAMTAADDYOTADLOCSDYYKADYKAEYKAOYKAOCYHTOTNYFXAXAAAYCYAYRSWEOSASIOFWGAGDEOESCXEHPFIOASOT"
    ]

    meta_data_handler = UnifiedDecoder(bdk.Network.REGTEST)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()

    excpected_output_cbor = meta_data_handler.last_used_collector.decoder.result.cbor

    expected_output = UR_OUTPUT.from_cbor(excpected_output_cbor)
    expected_descriptor_str = "wsh(sortedmulti(1,[5459f23b/48'/1'/0'/2']tpubDF5XHNeYNBkmPio8Zkw8zz6hBFoQ5BgXthUENZ7x51nbgNeC7exH6ZR8ZHSLEkLrKLxL1ELarJoDcZ1ZCAVCGALKA2V2KrNfegb2dPvdY5K,[5aa39a43/48'/1'/0'/2']tpubDDyGGnd9qGbDsccDSe2imVHJPd96WysYkMVAf95PWzbbCmmKHSW7vLxvrTW3HsAau9MWirkJsyaALGJwqwcReu3LZVMg6XbRgBNYTtKXeuD))#clq2twvr"
    assert expected_output.descriptor() == expected_descriptor_str

    ## encode_descriptor
    output = URTools.encode_ur_output(expected_descriptor_str)

    # reorder multisig parts and name them
    order = [1, 0]
    output.crypto_key.hd_keys = [output.crypto_key.hd_keys[i] for i in order]
    for name, hdkey in zip(["BIP39 2", "BIP39 1"], output.crypto_key.hd_keys):
        hdkey.name = name

    # URComparator.verbose_compare_output(output, expected_output)
    assert output.to_cbor() == expected_output.to_cbor()


def test_encode_descriptor_multi_sig3():
    """
    Source of test data: sparrow
    """
    parts = [
        "UR:CRYPTO-OUTPUT/TAADMETAADMSOEADAOAOLSTAADDLOSAOWKAXHDCLAXTEOTCPURDNVTCSCYMNNDEHIOFSLKTBPSAOTDLKMYNYCWGHHDKGVWJONNWKRNWMSEAAHDCXWKRYWNSOLDRYSBZODNOYNESESWKOBYAADWYAASKNHEJEGRSSUOHFSFTSWYISFRLFAHTAADEHOEADAEAOADAMTAADDYOTADLOCSDYYKADYKAEYKAOYKAOCYUOLGSGQZAXAAAYCYSBBEMTTDASIOFWGAGDEOESCXEOTAADDLOSAOWKAXHDCLAXCAGEVDGSKPPKSPOLCEGHDEEHSWFLSFCYSPPDMKGATOFDJLFWDYJLBGAMNLHLFTRKAAHDCXYNWNMTBKVDLTNEPTDPLALUEHGUEOOEMEFPDPSEYNDLREBYLYJYHYVWLNBTYLPKBSAHTAADEHOEADAEAOADAMTAADDYOTADLOCSDYYKADYKAEYKAOYKAOCYRDSPCMLPAXAAAYCYTLFPETAEASIOFWGAGDEOESCXEHTAADDLOSAOWKAXHDCLAXOTNYHPHFZOWEWDRLFNVELTBBFDRFCEOEIHCKTIFSENWKEMMTLDURCSOTNNOSTKNLAAHDCXHGLAGSHPLSFHVAVLOEWPJOFGHFAMJELOHFRLLPFZGANNKPLEETAEROPEECWEPRISAHTAADEHOEADAEAOADAMTAADDYOTADLOCSDYYKADYKAEYKAOYKAOCYIYDIWZBKAXAAAYCYHTMTPASPASIOFWGAGDEOESCXEYFTOXFPRS"
    ]

    meta_data_handler = UnifiedDecoder(bdk.Network.REGTEST)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()

    excpected_output_cbor = meta_data_handler.last_used_collector.decoder.result.cbor

    expected_output = UR_OUTPUT.from_cbor(excpected_output_cbor)
    expected_descriptor_str = "wsh(sortedmulti(2,[dc8dcab4/48'/1'/0'/2']tpubDFQ6uhn3kCZBSQBAsQPjrhidZiAkxM8ywxxQadsATpqUk7TxVLsSnZi6sDMwbZqWVrVDTnGQGYKRU4yZ8RQwVNNc7vyN1p8qJoxvbeVs2Yc,[bac81685/48'/1'/0'/2']tpubDFUSsDE7pGLWKiBYsWpXWVw6rdo19J2UNAkg8k2WLTtYTHrCXWHbFmUBswBq6DrDrMuKc7eK3kKuT1L7bm4u4avhG5wnAEgatJ7398H38JF,[6627f20a/48'/1'/0'/2']tpubDEa9phJRMmAjQVQbkAA4WGJdaRtXjNTLsqfsEF3NaxiKEqfbdgBe56pQhR7h1ZpTKWiCDRfHyraRxBnojJazxhefELoiv5QDLzT1ANZrXhU))#wnj5crml"
    assert expected_output.descriptor() == expected_descriptor_str

    ## encode_descriptor
    output = URTools.encode_ur_output(expected_descriptor_str)

    # reorder multisig parts and name them
    order = [1, 2, 0]
    output.crypto_key.hd_keys = [output.crypto_key.hd_keys[i] for i in order]
    for name, hdkey in zip(["BIP39 3", "BIP39 1", "BIP39 2"], output.crypto_key.hd_keys):
        hdkey.name = name

    # URComparator.verbose_compare_output(output, expected_output)
    assert output.to_cbor() == expected_output.to_cbor()
