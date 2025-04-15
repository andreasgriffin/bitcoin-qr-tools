import bdkpython as bdk

from bitcoin_qr_tools.data import ConverterMultisigWalletExport, Data, DataType


def test_descriptor():
    # test descriptor
    s = "wpkh([a42c6dd3/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*)#p3rdl64r"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.Descriptor
    assert isinstance(data.data, bdk.Descriptor)

    dump = data.dump()
    Data.from_dump(dump, network=bdk.Network.REGTEST).data_as_string() == s


def test_ConverterLegacyColdcardMultisigWalletExport():
    s = """
# Keystone Multisig setup file (created by Bitcoin Safe)
#
Name: keystone-multi
Policy: 2 of 3
Format: P2WSH

Derivation: m/1h/0h/0h
0439F926: xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu
Derivation: m/2h/0h/0h/2h
AB9A2E94: xpub6CJQ9dk1R9ssG4EcS3REdEJ24f5F4ahb5H7sKpP4a63jsjayxuqe6dJN4U3t7ce9sz3tCXSsP7AJKbsoa5y7vebHrhjF4vq65Yt2ZtZbCju
Derivation: m/3h/0h/0h/2h
0BF7F30E: xpub6EzEVsAwvggBeYfsqWdi4e9JFk2HWbcorybrDtiGjvhewVKmMtV41HDK311zbpWQYbWfMLiULAX32LqDZqo5bNrRyC8KKweRB23gBnDoArP"""
    data = Data.from_str(s, network=bdk.Network.BITCOIN)

    assert isinstance(data.data, ConverterMultisigWalletExport)
    assert data.data_type == DataType.MultisigWalletExport
    assert (
        data.data_as_string()
        == "#  Multisig setup file (created by Bitcoin Safe)\n#\nName: keystone-multi\nPolicy: 2 of 3\nFormat: P2WSH\n\nDerivation: m/1h/0h/0h\n0439F926: xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu\nDerivation: m/2h/0h/0h/2h\nAB9A2E94: xpub6CJQ9dk1R9ssG4EcS3REdEJ24f5F4ahb5H7sKpP4a63jsjayxuqe6dJN4U3t7ce9sz3tCXSsP7AJKbsoa5y7vebHrhjF4vq65Yt2ZtZbCju\nDerivation: m/3h/0h/0h/2h\n0BF7F30E: xpub6EzEVsAwvggBeYfsqWdi4e9JFk2HWbcorybrDtiGjvhewVKmMtV41HDK311zbpWQYbWfMLiULAX32LqDZqo5bNrRyC8KKweRB23gBnDoArP"
    )

    assert (
        Data.from_str(data.data_as_string(), network=bdk.Network.BITCOIN).data_as_string()
        == data.data_as_string()
    )


def test_ConverterLegacyColdcardMultisigWalletExport_simple():
    s = """
# Keystone Multisig setup file (created by Bitcoin Safe)
#
Name: keystone-multi
Policy: 2 of 3
Format: P2WSH
Derivation: m/1h/0h/0h

0439F926: xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu
AB9A2E94: xpub6CJQ9dk1R9ssG4EcS3REdEJ24f5F4ahb5H7sKpP4a63jsjayxuqe6dJN4U3t7ce9sz3tCXSsP7AJKbsoa5y7vebHrhjF4vq65Yt2ZtZbCju
0BF7F30E: xpub6EzEVsAwvggBeYfsqWdi4e9JFk2HWbcorybrDtiGjvhewVKmMtV41HDK311zbpWQYbWfMLiULAX32LqDZqo5bNrRyC8KKweRB23gBnDoArP"""
    data = Data.from_str(s, network=bdk.Network.BITCOIN)

    assert isinstance(data.data, ConverterMultisigWalletExport)
    assert data.data_type == DataType.MultisigWalletExport
    assert (
        data.data_as_string()
        == "#  Multisig setup file (created by Bitcoin Safe)\n#\nName: keystone-multi\nPolicy: 2 of 3\nFormat: P2WSH\n\nDerivation: m/1h/0h/0h\n0439F926: xpub6CnQkivUEH9bSbWVWfDLCtigKKgnSWGaVSRyCbN2QNBJzuvHT1vUQpgSpY1NiVvoeNEuVwk748Cn9G3NtbQB1aGGsEL7aYEnjVWgjj9tefu\nDerivation: m/1h/0h/0h\nAB9A2E94: xpub6CJQ9dk1R9ssG4EcS3REdEJ24f5F4ahb5H7sKpP4a63jsjayxuqe6dJN4U3t7ce9sz3tCXSsP7AJKbsoa5y7vebHrhjF4vq65Yt2ZtZbCju\nDerivation: m/1h/0h/0h\n0BF7F30E: xpub6EzEVsAwvggBeYfsqWdi4e9JFk2HWbcorybrDtiGjvhewVKmMtV41HDK311zbpWQYbWfMLiULAX32LqDZqo5bNrRyC8KKweRB23gBnDoArP"
    )

    assert (
        Data.from_str(data.data_as_string(), network=bdk.Network.BITCOIN).data_as_string()
        == data.data_as_string()
    )


def test_Converter_jade():

    s = """# Exported by Blockstream Jade
Name: hwi3374c2e55c4b
Policy: 1 of 3
Format: P2WSH
Derivation: m/48'/1'/0'/2'
14c949b4: tpubDDvtDSGt5JmgxgpRp3nyZj3ULZvFWuU9AaS6x3UwkNE6vaNgzd6oyKYEQUzSevUQs2ste5QznpbN8Nt5bVbZvrJFpCqw9UPXCtnCutEvEwW
Derivation: m/48'/1'/0'/2'
d8cf7475: tpubDEDUiUcwmoC92QJ2kGPQwtikGqLrjdyUfuRMhm5ab4nYmgRkkKPF9mp2FcunzMu9y5Ea2urGUJh4t1o7Wb6KjKddzJKcE8BoAyTWK6ughFK
Derivation: m/48'/1'/0'/2'
d5b43540: tpubDFnCcKU3iUF4sPeQC68r2ewDaBB7TvLmQBTs12hnNS8nu6CPjZPmzapp7Woz6bkFuLfSjSpg6gacheKBaWBhDnEbEpKtCnVFdQnfhYGkPQF        """
    data = Data.from_str(s, network=bdk.Network.REGTEST)

    assert isinstance(data.data, ConverterMultisigWalletExport)
    assert data.data_type == DataType.MultisigWalletExport
    assert (
        data.data_as_string()
        == "#  Multisig setup file (created by Bitcoin Safe)\n#\nName: hwi3374c2e55c4b\nPolicy: 1 of 3\nFormat: P2WSH\n\nDerivation: m/48h/1h/0h/2h\n14c949b4: tpubDDvtDSGt5JmgxgpRp3nyZj3ULZvFWuU9AaS6x3UwkNE6vaNgzd6oyKYEQUzSevUQs2ste5QznpbN8Nt5bVbZvrJFpCqw9UPXCtnCutEvEwW\nDerivation: m/48h/1h/0h/2h\nd8cf7475: tpubDEDUiUcwmoC92QJ2kGPQwtikGqLrjdyUfuRMhm5ab4nYmgRkkKPF9mp2FcunzMu9y5Ea2urGUJh4t1o7Wb6KjKddzJKcE8BoAyTWK6ughFK\nDerivation: m/48h/1h/0h/2h\nd5b43540: tpubDFnCcKU3iUF4sPeQC68r2ewDaBB7TvLmQBTs12hnNS8nu6CPjZPmzapp7Woz6bkFuLfSjSpg6gacheKBaWBhDnEbEpKtCnVFdQnfhYGkPQF"
    )

    assert (
        Data.from_str(data.data_as_string(), network=bdk.Network.REGTEST).data_as_string()
        == data.data_as_string()
    )


def test_parse_from_legacy_coldcard():
    s = """# Keystone Multisig setup file (created on 0439f926)
#
Name: MultiSig
Policy: 2 of 3
Format: P2WSH

Derivation: m/48'/0'/0'/2'
0439F926: Zpub74Jru6aftwwHxCUCWEvP6DgrfFsdA4U6ZRtQ5i8qJpMcC39yZGv3egBhQfV3MS9pZtH5z8iV5qWkJsK6ESs6mSzt4qvGhzJxPeeVS2e1zUG
Derivation: m/48'/0'/0'/2'
A32EFFFD: Zpub75UB4yd3NBeRmYLa6cjEMLH512cBgqS5SmVhhQoF6NFciXhKosNFQr74cjDAqtGapYBXJL7D3YN59kGr8d6aSNcrVNgZLLSS3Z1EHURN8qG
Derivation: m/48'/0'/0'/2'
95AF25EF: Zpub75PxF38JVVfjW4whYWpS7CMs4g88N7D187jnJx5RKPzRrxq3jMgCdRyz1ayQHrw9NhWbHmrzrB9UhpTxHwUWGSuHNzbdv9hZ6q74DBxpRQ6
"""

    data = Data.from_str(s, network=bdk.Network.BITCOIN)
    assert data.data_type == DataType.MultisigWalletExport
    assert (
        data.data_as_string()
        == "#  Multisig setup file (created by Bitcoin Safe)\n#\nName: MultiSig\nPolicy: 2 of 3\nFormat: P2WSH\n\nDerivation: m/48h/0h/0h/2h\n0439F926: xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf\nDerivation: m/48h/0h/0h/2h\nA32EFFFD: xpub6EuZLQYmVs16eNnxVEh175kFwJH2bEmVJGobDMjvxafSz9VxY9er5bvrmcLXHdjqmnsvvnuyF1GUG1RxQ17bhR8yvEBJm7LTcNc4vKY7xds\nDerivation: m/48h/0h/0h/2h\n95AF25EF: xpub6EqLWU42dB2QNuQ5w8nCrwq3zwnyGWYQyd3fpu27BcQG8adgTdxoJBonAU6kjcQQKxCzvEfm3e3sp5d4ZKVXXVRQor6PLvbafehtr8QwtgS"
    )

    assert isinstance(data.data, ConverterMultisigWalletExport)
    assert (
        data.data.to_custom_str(hardware_signer_name="Keystone")
        == "# Keystone Multisig setup file (created by Bitcoin Safe)\n#\nName: MultiSig\nPolicy: 2 of 3\nFormat: P2WSH\n\nDerivation: m/48h/0h/0h/2h\n0439F926: xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf\nDerivation: m/48h/0h/0h/2h\nA32EFFFD: xpub6EuZLQYmVs16eNnxVEh175kFwJH2bEmVJGobDMjvxafSz9VxY9er5bvrmcLXHdjqmnsvvnuyF1GUG1RxQ17bhR8yvEBJm7LTcNc4vKY7xds\nDerivation: m/48h/0h/0h/2h\n95AF25EF: xpub6EqLWU42dB2QNuQ5w8nCrwq3zwnyGWYQyd3fpu27BcQG8adgTdxoJBonAU6kjcQQKxCzvEfm3e3sp5d4ZKVXXVRQor6PLvbafehtr8QwtgS"
    )


def test_try_extract_sign_message_request_text():
    s = "signmessage m/84h/1h/0h/0/5 ascii:hello"

    data = Data.from_str(s, network=bdk.Network.BITCOIN)
    assert data.data_type == DataType.SignMessageRequest
    assert data.data_as_string() == '{"msg": "hello", "subpath": "m/84h/1h/0h/0/5 ", "addr_fmt": ""}'


def test_try_extract_sign_message_request():
    s = '{"msg": "hello", "subpath": "m/84h/1h/0h/0/5 ", "addr_fmt": "p2wpkh"}'

    data = Data.from_str(s, network=bdk.Network.BITCOIN)
    assert data.data_type == DataType.SignMessageRequest
    assert data.data_as_string() == '{"msg": "hello", "subpath": "m/84h/1h/0h/0/5 ", "addr_fmt": "p2wpkh"}'
