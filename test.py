from bitcoin_qrreader.bitcoin_qr import *


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

# test KeyStoreInfo
s = "[a42c6dd3/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks"
data = Data.from_str(s, network=bdk.Network.REGTEST)
assert data.data_type == DataType.KeyStoreInfo
assert data.data == {
    "xpub": "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks",
    "fingerprint": "a42c6dd3",
    "derivation_path": "m/84'/1'/0'",
    "further_derivation_path": None,
}

# test KeyStoreInfo with h instead of '
s = "[a42c6dd3/84h/1h/0h]tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks"
data = Data.from_str(s, network=bdk.Network.REGTEST)
assert data.data_type == DataType.KeyStoreInfo
assert data.data == {
    "xpub": "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks",
    "fingerprint": "a42c6dd3",
    "derivation_path": "m/84'/1'/0'",
    "further_derivation_path": None,
}

# test KeyStoreInfo with further_derivation_path
s = "[a42c6dd3/84'/1'/0']tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks/0/*"
data = Data.from_str(s, network=bdk.Network.REGTEST)
assert data.data_type == DataType.KeyStoreInfo
assert data.data == {
    "xpub": "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks",
    "fingerprint": "a42c6dd3",
    "derivation_path": "m/84'/1'/0'",
    "further_derivation_path": "/0/*",
}


# test slip132
s = "[7cf42c8e/84h/1h/0h]vpub5ZfBcsqfiq4GvTyyYpJW13W9KyZTT1TXNd4bvVk8TZ5ShYh2Bjfm5PyVhcSoLwAr23iRUvYtpza8wmCKPYu8ECKyZPAfwDaFniMjpzACeqJ"
data = Data.from_str(s, network=bdk.Network.REGTEST)
assert data.data_type == DataType.KeyStoreInfo
assert data.data == {
    "xpub": "tpubDDhLkT1BjU6gtrZ4firqd92X12x1KdwakUhLqqb3ZUb6Z2zBmGqyTxxbz4SksFRvdEUwbTFtHR7HQWv4DoaPi79UMfJpnZsTv85SNCfeePi",
    "fingerprint": "7cf42c8e",
    "derivation_path": "m/84'/1'/0'",
    "further_derivation_path": None,
}


# test slip132 multisig (the xpub is at a different derivation path)
s = "[7cf42c8e/48h/1h/0h/2h]Vpub5kwQ4Q4rGphWbu7SwK9TkPwgPkTKykZZLL22mavN7y9uH7gmQB8doAfx6sJrCtfam33p4vYUrZRdzYp8Ky5ogHB6ioUFA6XFCzM2wkeko6v"
data = Data.from_str(s, network=bdk.Network.REGTEST)
assert data.data_type == DataType.KeyStoreInfo
assert data.data == {
    "xpub": "tpubDE5U4jVviWBZ9iXA7ZEpYR8FM1oce2N2Pv16mfVjr7q9WRR2DJva6co8acMLAmhm8kkMJsFMRmaHL8v6rzc81hsvgcVzc3MTSfnrtwYZMMy",
    "fingerprint": "7cf42c8e",
    "derivation_path": "m/48'/1'/0'/2'",
    "further_derivation_path": None,
}

# test xpub
s = "tpubDDnGNapGEY6AZAdQbfRJgMg9fvz8pUBrLwvyvUqEgcUfgzM6zc2eVK4vY9x9L5FJWdX8WumXuLEDV5zDZnTfbn87vLe9XceCFwTu9so9Kks"
data = Data.from_str(s, network=bdk.Network.REGTEST)
assert data.data_type == DataType.Xpub
assert data.data == s

# test txid
s = "14cd7d7ec4ab969afcb1609a6638b89895ae023446fd523875b0e930fdcd1b67"
data = Data.from_str(s, network=bdk.Network.REGTEST)
assert data.data_type == DataType.Txid
assert data.data == s

# test tx
s = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502ad000101ffffffff0200f9029500000000160014b947c0de955cd2ccdfcd5b33198d2656834d0cd50000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"
data = Data.from_str(s, network=bdk.Network.REGTEST)
assert data.data_type == DataType.Tx
assert serialized_to_hex(data.data.serialize()) == s

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

# tx  in base43  (electrum)
s = "M2/VL:YG123EZA4VZ36QF7E*AJAOI/7XORPC8X8S69504C2ZZX493.ZQRA.UJ88O5YI7E$3JA.6OEVKFQW4V0+X4192T0+1Y5K3YUHZ.6Z*LXNN:GAB/BBU7T+H9SA2A7ALE8UJBLYVV6$$ZN1I.TY1M+8MOIOW/BWS/$KP1$0.FVDU/HUTTYT2PO5R0*3XWOF:LY4L0JQ3TPOAJ1QDE8A/0H+1O+D0TX+UE4KU44VE6QIAO:W0VG830-VQ+BF:.OANNB2GLOYXUU*4V2VCJS*RS2TC5JO2JLDEL.92F5PS3Y1EDY-G9-4C30S3F*-7V0BXB6R"
data = Data.from_str(s, network=bdk.Network.REGTEST)
assert data.data_type == DataType.Tx
assert (
    bytes(data.data.serialize()).hex()
    == "01000000000101324ffaac81edf89c4b318f42028116c6d19fc547884327e9fc8dce0c2e34a7650000000000fdffffff02dbad3d25000000001600140277d89eda5f5c3152595828c5239eda1cc045dc400d03000000000016001488aca5ab3813f3e09512487e30be0fa293ce2bf602473044022054634107fa26af77735d2eefa48618de2500cc0e852fd804a1816b85e58de671022010170c91c3423f324f7487456dfa0c485220bc7bc66f3e65ec90abe88731ad640121026c192a98c1fb5f84870e6833b4bc7a06f8d37f58ffa940428d3a3dca8809e4cca4020000"
)
