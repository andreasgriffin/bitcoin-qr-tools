from bitcoin_qr_tools.data import convert_slip132_to_bip32, is_slip132


def test_convert_slip132_to_bip32():
    key = "tpubD6NzVbkrYhZ4XzL5Dhayo67Gorv1YMS7j8pRUvVMd5odC2LBPLAygka9p7748JtSq82FNGPppFEz5xxZUdasBRCqJqXvUHq6xpnsMcYJzeh"
    assert not is_slip132(key)

    key = "upub5DMRSsh6mNaeiTXEzarZLvZezWp4cGhaDHjMz9iineDN8syqep2XHncDKFVtTUXY4fyKp12qDVVwdfq5rKkw2CDf5fy2gEHyh5NoTC6fiwm"
    expected = "tpubDCDqt7XXvhAYY9HSwrCXB7BXqYM4RXB8WFtKgtTXGa6u3U6EV1NJJRFTcuTRyhSY5Vreg1LP8aPdyiAPQGrDJLikkHoc7VQg6DA9NtUxHtj"
    assert is_slip132(key)
    assert convert_slip132_to_bip32(key) == expected

    key = "vpub5Y5a91QvDT3yog4bmgbqFo7GPXpRpozogzQeDArSPzsY8SKGHTgjSswhxhGkRonUQ9tyo9ZSQ1ecLKkVUyewWEUJZdwgUQycvG86FV7sdhZ"
    expected = "tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r"
    assert is_slip132(key)
    assert convert_slip132_to_bip32(key) == expected

    key = "Upub5T4XUooQzDXL58NCHk8ZCw9BsRSLCtnyHeZEExAq1XdnBFXiXVrHFuvvmh3TnCR7XmKHxkwqdACv68z7QKT1vwru9L1SZSsw8B2fuBvtSa6"
    expected = "tpubDF2rnouQaaYrUEy2JM1YD3RFzew4onawGM4X2Re67gguTf5CbHonBRiFGe3Xjz7DK88dxBFGf2i7K1hef3PM4cFKyUjcbJXddaY9F5tJBoP"
    assert is_slip132(key)
    assert convert_slip132_to_bip32(key) == expected

    key = "Vpub5mtnnUUL8u4oyRf5d2NZJqDypgmpx8FontedpqxNyjXTi6fLp8fmpp2wedS6UyuNpDgLDoVH23c6rYpFSEfB9jhdbD8gek2stjxhwJeE1Eq"
    expected = "tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP"
    assert is_slip132(key)
    assert convert_slip132_to_bip32(key) == expected

    # mainnet

    key = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"
    expected = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"
    assert is_slip132(key)
    assert convert_slip132_to_bip32(key) == expected

    key = "Zpub74Jru6aftwwHxCUCWEvP6DgrfFsdA4U6ZRtQ5i8qJpMcC39yZGv3egBhQfV3MS9pZtH5z8iV5qWkJsK6ESs6mSzt4qvGhzJxPeeVS2e1zUG"
    expected = "xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf"
    assert is_slip132(key)
    assert convert_slip132_to_bip32(key) == expected

    key = "Ypub6jUbbRukkGPp4DgJDD4HL2NKkSZ1UPk111mg59XtJRQZHvJ6XqvJzrntik9U4jCFQkgrBqevdKLPMdYZXU9KAGhKpMhW5XujwqiQ7Csmm4Z"
    expected = "xpub6DkFAXWQ2dHxnMKoSBogHrw1rgNJKR4umdbnNVNTYeCGcduxWnNUHgGptqEQWPKRmeW4Zn4FHSbLMBKEWYaMDYu47Ytg6DdFnPNt8hwn5mE"
    assert is_slip132(key)
    assert convert_slip132_to_bip32(key) == expected

    key = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP"
    expected = "xpub6C6nQwHaWbSrzs5tZ1q7m5R9cPK9eYpNMFesiXsYrgc1P8bvLLAet9JfHjYXKjToD8cBRswJXXbbFpXgwsswVPAZzKMa1jUp2kVkGVUaJa7"
    assert is_slip132(key)
    assert convert_slip132_to_bip32(key) == expected
