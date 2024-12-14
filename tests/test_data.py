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
