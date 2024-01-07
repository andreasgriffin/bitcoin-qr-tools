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


def test_SignerInfo():

    # test SignerInfo
    s = "[a42c6dd3/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.SignerInfo
    assert data.data == SignerInfo(
        **{
            "xpub": "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks",
            "fingerprint": "a42c6dd3",
            "key_origin": "m/84'/1'/0'",
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
            "key_origin": "m/84'/1'/0'",
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
            "key_origin": "m/84'/1'/0'",
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
            "key_origin": "m/84'/1'/0'",
        }
    )

    # test slip132 multisig (the xpub is at a different derivation path)
    s = "[7cf42c8e/48h/1h/0h/2h]Vpub5kwQ4Q4rGphWbu7SwK9TkPwgPkTKykZZLL22mavN7y9uH7gmQB8doAfx6sJrCtfam33p4vYUrZRdzYp8Ky5ogHB6ioUFA6XFCzM2wkeko6v"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.SignerInfo
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
        "key_origin": "m/48'/0'/0'/2'",
        "xpub": "tpubDE5U4jVviWBZ9iXA7ZEpYR8FM1oce2N2Pv16mfVjr7q9WRR2DJva6co8acMLAmhm8kkMJsFMRmaHL8v6rzc81hsvgcVzc3MTSfnrtwYZMMy",
        "derivation_path": None,
        "name": None,
        "first_address": None,
    }


def test_xpub():

    # test xpub
    s = "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.Xpub
    assert data.data == s


def test_txid():

    # test txid
    s = "14cd7d7ec4ab969afcb1609a6638b89895ae023446fd523875b0e930fdcd1b67"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.Txid
    assert data.data == s


def test_tx():

    # test tx
    s = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502ad000101ffffffff0200f9029500000000160014b947c0de955cd2ccdfcd5b33198d2656834d0cd50000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.Tx
    assert serialized_to_hex(data.data.serialize()) == s

    # tx  in base43  (electrum)
    s = "M2/VL:YG123EZA4VZ36QF7E*AJAOI/7XORPC8X8S69504C2ZZX493.ZQRA.UJ88O5YI7E$3JA.6OEVKFQW4V0+X4192T0+1Y5K3YUHZ.6Z*LXNN:GAB/BBU7T+H9SA2A7ALE8UJBLYVV6$$ZN1I.TY1M+8MOIOW/BWS/$KP1$0.FVDU/HUTTYT2PO5R0*3XWOF:LY4L0JQ3TPOAJ1QDE8A/0H+1O+D0TX+UE4KU44VE6QIAO:W0VG830-VQ+BF:.OANNB2GLOYXUU*4V2VCJS*RS2TC5JO2JLDEL.92F5PS3Y1EDY-G9-4C30S3F*-7V0BXB6R"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.Tx
    assert (
        bytes(data.data.serialize()).hex()
        == "01000000000101324ffaac81edf89c4b318f42028116c6d19fc547884327e9fc8dce0c2e34a7650000000000fdffffff02dbad3d25000000001600140277d89eda5f5c3152595828c5239eda1cc045dc400d03000000000016001488aca5ab3813f3e09512487e30be0fa293ce2bf602473044022054634107fa26af77735d2eefa48618de2500cc0e852fd804a1816b85e58de671022010170c91c3423f324f7487456dfa0c485220bc7bc66f3e65ec90abe88731ad640121026c192a98c1fb5f84870e6833b4bc7a06f8d37f58ffa940428d3a3dca8809e4cca4020000"
    )

    # raw transaction splitted with UR  (like sparrow)
    parts = [
        "UR:BYTES/162-3/LPCSOEAXCSVTCYHKMSLGOLHDGRVOVLHLGRHDCEFLTBCXCFMUAEAEAEAECMAEBBBGSOVTSOGTTBSTCEZESTRFZMCMZEWDBKBSRORFHLAOFLDYFYAOCXHHLOTYTSVLAHNECMSWYLGTWMRHKPGLZERDLDYTDRCNKGKIASTAJKDMHKROOSTBBAOLCXKP",
        "UR:BYTES/164-3/LPCSOXAXCSVTCYHKMSLGOLHDGRRDFSHHGRHDCEFLTSCLJTJZJEGTVEHHRHISMNLTZMNLMEPRRYHFDYUTFWISDEFZSSVLPFGLJKRPJSEYPRBGFYAOCXHHLODTDECEZSNTRPAYCKGSWMRHKPGLVSRDNTBDAAISIOWSDNWFGRNSURFEJYFDBSCMFHVA",
        "UR:BYTES/165-3/LPCSONAXCSVTCYHKMSLGOLHDGRFNVYKIIOROWFJYHHTSIODMLKBBPLLOVYVSDAAADTHTWYVWGSDTIETSDESFDMWDJKJKONASRHNTHELFINDLNNATMTKTMSTESGTBRHGLFHFTYATTCSVSASDKASASEYYKSNGLBTRDTSURZEDMHKROOSTBETOLNBMD",
    ]
    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.Tx
    assert (
        serialized_to_hex(data.data.serialize())
        == "0100000000010177ff6b4de45caf689a95367958ff6b912c2385d4d7563a09ba41cb0a2c30f5220000000000fdffffff02a0cee90100000000160014f22e4b1c92222a38b286fdd39ee2e35d4b581c47d62019930000000016001412c9e0c94dd6c71cfec7bcff16feea0a0fb8bc5d0247304402205c88d4d7e3059f16c6f74debb9754efeba89f92a237b7d09d9732e59b8a7d6de02202ce0ef338af77ebd8c14ae88f7e83116e0ba27a89aee7829ef70d1fc8d99af06012102802e1fda05b62b1f071d35bcd129fc0f9cf3517c6af7b3bb0ce76d76c7de068d00000000"
    )


def test_psbt():

    # psbt
    s = "cHNidP8BAHEBAAAAAXgQzjk+DTWQTPUtRMbYiheC0jfbipvw+jQ5lidmyABjAAAAAAD9////AgDh9QUAAAAAFgAUbBuOQOlcnz8vpruh2Kb3CFr4vlhkEQ2PAAAAABYAFN1n2hvBWYzshD42xwQzy9XYoji3BAEAAAABAKoCAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BQKYAAEB/////wIA+QKVAAAAABYAFLlHwN6VXNLM381bMxmNJlaDTQzVAAAAAAAAAAAmaiSqIant4vYcP3HR3v0/qZnfo2lTdVxpBol5mWK0i+vYNpdOjPkBIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBHwD5ApUAAAAAFgAUuUfA3pVc0szfzVszGY0mVoNNDNUiBgISCnRxeOxzC0MgK01AmiIRLrgS1AyIqKeBkdwL+nt/6RikLG3TVAAAgAEAAIAAAACAAAAAAAAAAAAAACICAlQcwExiTUk9f7olLkwPlQpiregRHc9jXXFJBlMoucgNGKQsbdNUAACAAQAAgAAAAIAAAAAAAQAAAAA="
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.PSBT
    assert data.data.serialize() == s

    # psbt  in hex
    s = "70736274ff01007101000000017810ce393e0d35904cf52d44c6d88a1782d237db8a9bf0fa3439962766c800630000000000fdffffff0200e1f505000000001600146c1b8e40e95c9f3f2fa6bba1d8a6f7085af8be5864110d8f00000000160014dd67da1bc1598cec843e36c70433cbd5d8a238b704010000000100aa020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050298000101ffffffff0200f9029500000000160014b947c0de955cd2ccdfcd5b33198d2656834d0cd50000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9012000000000000000000000000000000000000000000000000000000000000000000000000001011f00f9029500000000160014b947c0de955cd2ccdfcd5b33198d2656834d0cd5220602120a747178ec730b43202b4d409a22112eb812d40c88a8a78191dc0bfa7b7fe918a42c6dd354000080010000800000008000000000000000000000220202541cc04c624d493d7fba252e4c0f950a62ade8111dcf635d7149065328b9c80d18a42c6dd3540000800100008000000080000000000100000000"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.PSBT
    assert (
        data.data.serialize()
        == "cHNidP8BAHEBAAAAAXgQzjk+DTWQTPUtRMbYiheC0jfbipvw+jQ5lidmyABjAAAAAAD9////AgDh9QUAAAAAFgAUbBuOQOlcnz8vpruh2Kb3CFr4vlhkEQ2PAAAAABYAFN1n2hvBWYzshD42xwQzy9XYoji3BAEAAAABAKoCAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BQKYAAEB/////wIA+QKVAAAAABYAFLlHwN6VXNLM381bMxmNJlaDTQzVAAAAAAAAAAAmaiSqIant4vYcP3HR3v0/qZnfo2lTdVxpBol5mWK0i+vYNpdOjPkBIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBHwD5ApUAAAAAFgAUuUfA3pVc0szfzVszGY0mVoNNDNUiBgISCnRxeOxzC0MgK01AmiIRLrgS1AyIqKeBkdwL+nt/6RikLG3TVAAAgAEAAIAAAACAAAAAAAAAAAAAACICAlQcwExiTUk9f7olLkwPlQpiregRHc9jXXFJBlMoucgNGKQsbdNUAACAAQAAgAAAAIAAAAAAAQAAAAA="
    )

    # psbt  in base43
    s = "8QL7:6+K4/8G8R4H280VS:ZETHWYA8T0M0+TDB*:DO-RPJ719-L2IK:U-W03F*YY..Z*6BL:RK1/6FL6$C5WF773J1ZNXKSDX:.65$P6KFSE06:OJGR+PVSJ6AVXAU1B5KJ8UPKDRA4.FF31PGAS9CA4DTGWA9DTMCPK2.XWBVHDPG*BTNN7X7M$JKN2KP$BX0CGO.F83U.HQ4LEU4HX772U7F8T33H/M80-9-IJF-VZ+EEJO8I*8ZXITNQRX8T/2SI/:4L*-85:4QUI5DIN2:DO$GH2Y:MURO$AKD0HTWFKTG+.JUS3V++NNQTGUL1FF3N50PCQJ$R5+4DV/D*1RQ$86$0HZ-P8+T/H6I62SHZJ2T9OKXXH+M-1+/K$YXT31G3TMS8ZR9ZCLU4$V:LLMBDH*NEZA-3ES.Q$DKEZSRG3X*:909+QWR80P2KBUIY0U/K5NCQU/+G2.T*C6JPFSNRT-2I4.Z:BNIGOO.*ZT9VENQ94R55N"
    data = Data.from_str(s, network=bdk.Network.REGTEST)
    assert data.data_type == DataType.PSBT
    assert (
        data.data.serialize()
        == "cHNidP8BAHEBAAAAATJP+qyB7ficSzGPQgKBFsbRn8VHiEMn6fyNzgwuNKdlAAAAAAD9////AtutPSUAAAAAFgAUAnfYntpfXDFSWVgoxSOe2hzARdxADQMAAAAAABYAFIispas4E/PglRJIfjC+D6KTziv2pAIAAAABAR9AvkAlAAAAABYAFCwiv4G38qX3bI3ejFeBhmz/ynVEIgYCbBkqmMH7X4SHDmgztLx6BvjTf1j/qUBCjTo9yogJ5MwYfPQsjlQAAIABAACAAAAAgAEAAAAKAAAAACICAg4ln5Ey8qPfMRXwjlp2W9igSm5Qm1IMi9IaL24SoFLQGHz0LI5UAACAAQAAgAAAAIABAAAAHAAAAAAiAgI4gc65DfdDJ3bI9FMX9fwq7NgKZcY8YCHHAjRWrvPC/Rh89CyOVAAAgAEAAIAAAACAAAAAABkAAAAA"
    )

    # psbt , splitted according to specter
    def split_string_by_length(input_string, length):
        return [input_string[i : i + length] for i in range(0, len(input_string), length)]

    s = "cHNidP8BAHEBAAAAAXgQzjk+DTWQTPUtRMbYiheC0jfbipvw+jQ5lidmyABjAAAAAAD9////AgDh9QUAAAAAFgAUbBuOQOlcnz8vpruh2Kb3CFr4vlhkEQ2PAAAAABYAFN1n2hvBWYzshD42xwQzy9XYoji3BAEAAAABAKoCAAAAAAEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BQKYAAEB/////wIA+QKVAAAAABYAFLlHwN6VXNLM381bMxmNJlaDTQzVAAAAAAAAAAAmaiSqIant4vYcP3HR3v0/qZnfo2lTdVxpBol5mWK0i+vYNpdOjPkBIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBHwD5ApUAAAAAFgAUuUfA3pVc0szfzVszGY0mVoNNDNUiBgISCnRxeOxzC0MgK01AmiIRLrgS1AyIqKeBkdwL+nt/6RikLG3TVAAAgAEAAIAAAACAAAAAAAAAAAAAACICAlQcwExiTUk9f7olLkwPlQpiregRHc9jXXFJBlMoucgNGKQsbdNUAACAAQAAgAAAAIAAAAAAAQAAAAA="
    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
    splitted = split_string_by_length(s, 10)
    for part in [f"p{i+1}of{len(splitted)} {s}" for i, s in enumerate(splitted)]:
        meta_data_handler.add(part)

    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.PSBT
    assert data.data.serialize() == s


def test_checksum():
    # checksum test
    descriptor = "raw(deadbeef)"
    assert add_checksum_to_descriptor(descriptor).split("#")[1] == "89f8spxm"

    # checksum test
    descriptor = "wpkh([189cf85e/84'/1'/0']tpubDDkYCWGii5pUuqqqvh9vRqyChQ88aEGZ7z7xpwDzAQ87SpNrii9MumksW8WSqv2aYEBssKYF5KVeY9kmoreJrvQSB2dgCz11TXu81YhyaqP/0/*)"
    assert add_checksum_to_descriptor(descriptor).split("#")[1] == "arpc0qa2"

    # checksum test
    parts = [
        "wsh(sortedmulti(2,tprv8ZgxMBicQKsPeXkN69E47nqEZhrdWZkRBrzsZjzYQGjbr85QApCLuRCgKHTnfaiB9BZCDHrewdC8cTsyd54yGHZJxsvVvuB719VqYVu8eSz/84'/1'/0'/0/*,tprv8ZgxMBicQKsPeVD8mgZXgNgqTgGUhsv9qtHiRjhrvHL2ecXWhiCd4okHeC6sdFvs1rNYmwWf5Sa3B2PvhrZ1MHcCK8qPJqTSnZ9nLnywUGA/84'/1'/0'/0/*,tprv8ZgxMBicQKsPe3ca8xqj6BNa3Lb9pfyNyYaUy1y4AUCqTSAYwmhAMNnEHnBYtLgggRGrYt8BxcBwedNMnXFbWSxrtEzcJGu9L3k1BBVTNzD/84'/1'/0'/0/*))"
    ]
    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.Descriptor, "Wrong type"
    assert (
        data.data_as_string()
        == "wsh(sortedmulti(2,tprv8ZgxMBicQKsPeXkN69E47nqEZhrdWZkRBrzsZjzYQGjbr85QApCLuRCgKHTnfaiB9BZCDHrewdC8cTsyd54yGHZJxsvVvuB719VqYVu8eSz/84'/1'/0'/0/*,tprv8ZgxMBicQKsPeVD8mgZXgNgqTgGUhsv9qtHiRjhrvHL2ecXWhiCd4okHeC6sdFvs1rNYmwWf5Sa3B2PvhrZ1MHcCK8qPJqTSnZ9nLnywUGA/84'/1'/0'/0/*,tprv8ZgxMBicQKsPe3ca8xqj6BNa3Lb9pfyNyYaUy1y4AUCqTSAYwmhAMNnEHnBYtLgggRGrYt8BxcBwedNMnXFbWSxrtEzcJGu9L3k1BBVTNzD/84'/1'/0'/0/*))#5j8fff0h"
    )

    # checksum test (sparrow)
    descriptor = "wpkh([7d315cd9/84h/1h/0h]tpubDCUCSorYswSAurXv7ZcwfkPR8ms2fmxkEW7LFHuLs85wsCngaNAEVFkAvZSabsnz2VH6NvH4uFd4tZ8J3PSaVaxchE8QCd9wxak5Sugnd9p/<0;1>/*)"
    assert add_checksum_to_descriptor(descriptor).split("#")[1] == "3gahv2xk"

    # checksum test multipath_descriptor (created with sparrow pdf)
    parts = [
        "wpkh([7d315cd9/84h/1h/0h]tpubDCUCSorYswSAurXv7ZcwfkPR8ms2fmxkEW7LFHuLs85wsCngaNAEVFkAvZSabsnz2VH6NvH4uFd4tZ8J3PSaVaxchE8QCd9wxak5Sugnd9p/<0;1>/*)"
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
        == "wpkh([7d315cd9/84'/1'/0']tpubDCUCSorYswSAurXv7ZcwfkPR8ms2fmxkEW7LFHuLs85wsCngaNAEVFkAvZSabsnz2VH6NvH4uFd4tZ8J3PSaVaxchE8QCd9wxak5Sugnd9p/<0;1>/*)#xqqeqtvt"
    )
    # however if one replaces again the h by ', one gets the sparrow checksum
    assert (
        replace_in_descriptor(data.data_as_string(), "'", "h")
        == "wpkh([7d315cd9/84h/1h/0h]tpubDCUCSorYswSAurXv7ZcwfkPR8ms2fmxkEW7LFHuLs85wsCngaNAEVFkAvZSabsnz2VH6NvH4uFd4tZ8J3PSaVaxchE8QCd9wxak5Sugnd9p/<0;1>/*)#3gahv2xk"
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

    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
    for part in parts:
        meta_data_handler.add(part)
    assert meta_data_handler.is_complete()
    data = meta_data_handler.get_complete_data()
    assert data.data_type == DataType.SignerInfos, "Wrong type"
    # bdk returns '  instead of h  (which sparrrow does), so the checksum is different
    assert (
        data.data_as_string()
        == """[SignerInfo(fingerprint='0F056943', key_origin="m/44'/1'/0'", xpub='tpubDCiHGUNYdRRBPNYm7CqeeLwPWfeb2ZT2rPsk4aEW3eUoJM93jbBa7hPpB1T9YKtigmjpxHrB1522kSsTxGm9V6cqKqrp1EDaYaeJZqcirYB', derivation_path=None, name='p2pkh', first_address='mtHSVByP9EYZmB26jASDdPVm19gvpecb5R'), SignerInfo(fingerprint='0F056943', key_origin="m/49'/1'/0'", xpub='tpubDCDqt7XXvhAYY9HSwrCXB7BXqYM4RXB8WFtKgtTXGa6u3U6EV1NJJRFTcuTRyhSY5Vreg1LP8aPdyiAPQGrDJLikkHoc7VQg6DA9NtUxHtj', derivation_path=None, name='p2sh-p2wpkh', first_address='2NCAJ5wD4GvmW32GFLVybKPNphNU8UYoEJv'), SignerInfo(fingerprint='0F056943', key_origin="m/84'/1'/0'", xpub='tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r', derivation_path=None, name='p2wpkh', first_address='bcrt1qupyd58ndsh7lut0et0vtrq432jvu9jtdx8fgyv'), SignerInfo(fingerprint='0F056943', key_origin="m/48'/1'/0'/1'", xpub='tpubDF2rnouQaaYrUEy2JM1YD3RFzew4onawGM4X2Re67gguTf5CbHonBRiFGe3Xjz7DK88dxBFGf2i7K1hef3PM4cFKyUjcbJXddaY9F5tJBoP', derivation_path=None, name='p2sh-p2wsh', first_address=None), SignerInfo(fingerprint='0F056943', key_origin="m/48'/1'/0'/2'", xpub='tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP', derivation_path=None, name='p2wsh', first_address=None), SignerInfo(fingerprint='0F056943', key_origin="m/45'", xpub='tpubD8NXmKsmWp3a3DXhbihAYbYLGaRNVdTnr6JoSxxfXYQcmwVtW2hv8QoDwng6JtEonmJoL3cNEwfd2cLXMpGezwZ2vL2dQ7259bueNKj9C8n', derivation_path=None, name='p2sh', first_address=None)]"""
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
    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
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
    meta_data_handler = MetaDataHandler(bdk.Network.REGTEST)
    exceptionwas_raised = False
    try:
        for part in parts:
            meta_data_handler.add(part)
    except DecodingException:
        exceptionwas_raised = True
    assert exceptionwas_raised
