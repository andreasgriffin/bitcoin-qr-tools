import base64
import binascii
import enum
import hashlib
import json
import logging
import re
import urllib.parse
from decimal import Decimal
from os import fdopen
from typing import Any, Dict, List, Optional

import base58
import bdkpython as bdk

from .multipath_descriptor import MultipathDescriptor

BITCOIN_BIP21_URI_SCHEME = "bitcoin"
logger = logging.getLogger(__name__)


def is_bitcoin_address(s, network: bdk.Network):
    try:
        bdkaddress = bdk.Address(s, network)
        return bool(bdkaddress) and bdkaddress.is_valid_for_network(network=network)
    except:
        return False


class InvalidBitcoinURI(Exception):
    pass


def serialized_to_hex(serialized):
    return bytes(serialized).hex()


def hex_to_serialized(hex_string):
    return bytes.fromhex(hex_string)


def decode_bip21_uri(uri: str, network: bdk.Network) -> dict:
    """Raises InvalidBitcoinURI on malformed URI."""
    TOTAL_COIN_SUPPLY_LIMIT_IN_BTC = 21000000
    COIN = 100000000

    if not isinstance(uri, str):
        raise InvalidBitcoinURI(f"expected string, not {repr(uri)}")

    if ":" not in uri:
        if is_bitcoin_address(uri, network=network):
            return {"address": uri}
        else:
            raise InvalidBitcoinURI("Not a bitcoin address")

    u = urllib.parse.urlparse(uri)
    if u.scheme.lower() != BITCOIN_BIP21_URI_SCHEME:
        raise InvalidBitcoinURI("Not a bitcoin URI")
    address = u.path

    # python for android fails to parse query
    if address.find("?") > 0:
        address, query = u.path.split("?")
        pq = urllib.parse.parse_qs(query)
    else:
        pq = urllib.parse.parse_qs(u.query)

    for k, v in pq.items():
        if len(v) != 1:
            raise InvalidBitcoinURI(f"Duplicate Key: {repr(k)}")

    out: Dict[str, Any] = {k: v[0] for k, v in pq.items()}
    if address:
        if not is_bitcoin_address(address, network=network):
            raise InvalidBitcoinURI(f"Invalid bitcoin address: {address}")
        out["address"] = address
    if "amount" in out:
        am = out["amount"]
        try:
            m = re.match(r"([0-9.]+)X([0-9])", am)
            if m:
                amount = Decimal(m.group(1)) * pow(Decimal(10), int(m.group(2)) - 8)
            else:
                amount = Decimal(am) * COIN
            if amount > TOTAL_COIN_SUPPLY_LIMIT_IN_BTC * COIN:
                raise InvalidBitcoinURI(f"amount is out-of-bounds: {amount!r} BTC")
            out["amount"] = int(amount)
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'amount' field: {repr(e)}") from e
    if "message" in out:
        out["message"] = out["message"]
        out["memo"] = out["message"]
    if "time" in out:
        try:
            out["time"] = int(out["time"])
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'time' field: {repr(e)}") from e
    if "exp" in out:
        try:
            out["exp"] = int(out["exp"])
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'exp' field: {repr(e)}") from e
    if "sig" in out:
        try:
            out["sig"] = serialized_to_hex(out["sig"])
        except Exception as e:
            raise InvalidBitcoinURI(f"failed to parse 'sig' field: {repr(e)}") from e

    return out


def is_xpub(s: str) -> bool:
    if not s.isalnum():
        return False
    first_four_letters = s[:4]
    return first_four_letters.endswith("pub")


class SignerInfo:
    def __init__(
        self,
        fingerprint: str,
        key_origin: str,
        xpub: str,
        derivation_path: Optional[str] = None,
        name: Optional[str] = None,
        first_address: Optional[str] = None,
    ) -> None:
        self.fingerprint = fingerprint
        self.key_origin = self.format_key_origin(key_origin)
        self.xpub = xpub
        self.derivation_path = derivation_path
        self.name = name
        self.first_address = first_address

    def format_key_origin(self, value):
        assert value.startswith("m/"), "The value must start with m/"
        return value.replace("'", "h")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.__dict__})"

    def __str__(self) -> str:
        return f"{self.__dict__}"

    def __eq__(self, other: object) -> bool:
        return self.__dict__ == other.__dict__


def extract_signer_info(s: str) -> SignerInfo:
    """
    Splits 1 keystore,e.g. "[a42c6dd3/84'/1'/0']xpub/0/*"
    into fingerprint, key_origin, xpub, wallet_path

    It also replaces the "'" into "h"

    It overwrites fingerprint, key_origin, xpub  in default_keystore.
    """

    def key_origin_contains_valid_characters(s: str) -> bool:
        # Matches strings that consist of 'h', '/', digits, and optionally ends with a single quote
        return re.fullmatch("[mh/0-9']*", s) is not None

    def extract_groups(string: str, pattern):
        match = re.match(pattern, string)
        if match is None:
            raise Exception(f"'{string}' does not match the required pattern!")
        return match.groups()

    groups = extract_groups(s, r"\[(.*?)\/(.*?)\](.*?)(\/.*?)?$")

    key_origin = "m/" + groups[1].replace("'", "h")
    # guard against false positive detections
    assert key_origin_contains_valid_characters(key_origin)

    return SignerInfo(
        fingerprint=groups[0],
        key_origin=key_origin,
        xpub=groups[2],
        derivation_path=groups[3],
    )


def is_valid_bitcoin_hash(hash: str) -> bool:
    import re

    if re.match("^[a-f0-9]{64}$", hash):
        return True
    else:
        return False


def is_valid_wallet_fingerprint(fingerprint: str) -> bool:
    import re

    if re.match("^[a-fA-F0-9]{8}$", fingerprint):
        return True
    else:
        return False


###############  here is the simplified electrum base43 code
def base43_decode(v: str):
    __b43chars = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:"
    assert len(__b43chars) == 43
    __b43chars_inv = {v: k for k, v in enumerate(__b43chars)}

    base = 43
    num = 0

    # Remove leading zeros and adjust length
    v = v.lstrip("0")

    # Convert each character to a number using the inverse character map
    for char in v:
        num = num * base + __b43chars_inv[ord(char)]

    # Convert the number to bytes
    return num.to_bytes((num.bit_length() + 7) // 8, "big")


################ here is the slip132 part
### see https://github.com/satoshilabs/slips/blob/master/slip-0132.md


def get_slip132_version_bytes(slip132_key: str) -> bytes:
    """Get the version bytes from a SLIP-132 key."""
    raw_extended_key = base58.b58decode(slip132_key)
    return raw_extended_key[:4]


# Mapping of SLIP-132 version bytes to BIP32 version bytes
version_bytes_map = {
    bytes.fromhex("04b24746"): bytes.fromhex("0488b21e"),  # zpub to xpub
    bytes.fromhex("04b2430c"): bytes.fromhex("0488ade4"),  # zprv to xprv
    bytes.fromhex("049d7cb2"): bytes.fromhex("0488b21e"),  # ypub to xpub
    bytes.fromhex("049d7878"): bytes.fromhex("0488ade4"),  # yprv to xprv
    bytes.fromhex("0295b43f"): bytes.fromhex("0488b21e"),  # Ypub to xpub
    bytes.fromhex("0295b005"): bytes.fromhex("0488ade4"),  # Yprv to xprv
    bytes.fromhex("02aa7ed3"): bytes.fromhex("0488b21e"),  # Zpub to xpub
    bytes.fromhex("02aa7a99"): bytes.fromhex("0488ade4"),  # Zprv to xprv
    bytes.fromhex("045f1cf6"): bytes.fromhex("043587cf"),  # vpub to tpub
    bytes.fromhex("045f18bc"): bytes.fromhex("04358394"),  # vprv to tprv
    bytes.fromhex("044a5262"): bytes.fromhex("043587cf"),  # upub to tpub
    bytes.fromhex("044a4e28"): bytes.fromhex("04358394"),  # uprv to tprv
    bytes.fromhex("024289ef"): bytes.fromhex("043587cf"),  # Upub to tpub
    bytes.fromhex("024285b5"): bytes.fromhex("04358394"),  # Uprv to tprv
    bytes.fromhex("02575483"): bytes.fromhex("043587cf"),  # Vpub to tpub
    bytes.fromhex("02575048"): bytes.fromhex("04358394"),  # Vprv to tprv
}


def base58check_decode(s: str) -> bytes:
    """Decode a Base58Check encoded string to bytes"""
    # Decode the string
    data = base58.b58decode(s)

    # Split the data into the payload and the checksum
    check_sum = data[-4:]
    payload = data[:-4]

    # Calculate the checksum of the payload
    calculated_check_sum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    # Compare the calculated checksum with the checksum from the data
    if check_sum != calculated_check_sum:
        raise ValueError("Invalid checksum")

    return payload


def convert_slip132_to_bip32(slip132_key: str) -> str:
    """Convert a SLIP-132 extended key to a BIP32 extended key."""
    raw_extended_key = base58check_decode(slip132_key)
    slip132_version_bytes = raw_extended_key[:4]

    # Lookup the corresponding BIP32 version bytes
    bip32_version_bytes = version_bytes_map.get(slip132_version_bytes)
    if bip32_version_bytes is None:
        raise ValueError("Unsupported SLIP-132 version bytes")

    # Replace the version bytes of the raw key
    replaced_version_key = bip32_version_bytes + raw_extended_key[4:]

    # Calculate the checksum of the replaced version key
    check_sum = hashlib.sha256(hashlib.sha256(replaced_version_key).digest()).digest()[:4]

    # Encode the replaced version key + checksum into Base58
    bip32_key = base58.b58encode(replaced_version_key + check_sum).decode()

    return bip32_key


def is_slip132(key: str) -> bool:
    try:
        return get_slip132_version_bytes(key) in version_bytes_map
    except:
        return False


def is_ndjson_with_keys(s: str, keys: List[str]):
    """
    Checks if the input string s is newline-delimited JSON and each JSON object contains the specified keys.

    Args:
    s (str): The input string to check.
    keys (list of str): The keys that must be present in each JSON object.

    Returns:
    bool: True if the string is newline-delimited JSON and each object contains the specified keys, False otherwise.
    """
    lines = s.splitlines()

    # Check if there's at least one line
    if not lines:
        return False

    for line in lines:
        try:
            obj = json.loads(line)
            # Check if all specified keys are present in the JSON object
            if not all(key in obj for key in keys):
                logger.debug(f"ndjson check: Not all required keys {keys} are present in {obj}")
                return False
        except json.JSONDecodeError:
            return False

    return True


def is_bip329(s: str) -> bool:
    try:
        return is_ndjson_with_keys(s, keys=["type", "ref", "label"])
    except:
        return False


class DataType(enum.Enum):
    Bip21 = enum.auto()  # https://bips.dev/21/
    Descriptor = enum.auto()
    MultiPathDescriptor = enum.auto()
    Xpub = enum.auto()
    Fingerprint = enum.auto()
    SignerInfo = enum.auto()  # FingerPrint, Derivation path, Xpub
    PSBT = enum.auto()
    Txid = enum.auto()
    Tx = enum.auto()
    SignerInfos = enum.auto()  # a list of SignerInfo
    LabelsBip329 = enum.auto()

    @classmethod
    def from_value(cls, value: int) -> "DataType":
        min_value = min([member.value for member in cls])
        return list(cls)[value - min_value]

    @classmethod
    def from_name(cls, value: str) -> "DataType":
        names = [member.name for member in cls]
        return list(cls)[names.index(value)]


class DecodingException(Exception):
    pass


class InconsistentDescriptors(Exception):
    pass


class WrongNetwork(Exception):
    pass


class Data:
    """
    Recognized bitcoin data in a string, gives the data and the DataType
    """

    def __init__(self, data, data_type: DataType) -> None:
        self.data = data
        self.data_type = data_type

    def dump(self) -> Dict:
        return {"data": self.data_as_string(), "data_type": self.data_type.name}

    @classmethod
    def from_dump(cls, d: Dict, network: bdk.Network) -> "Data":
        data = cls.from_str(d["data"], network=network)
        d["data_type"] = DataType.from_name(d["data_type"])
        assert d["data_type"] == data.data_type
        return data

    def data_as_string(self) -> str:
        if isinstance(self.data, str):
            return self.data
        if self.data_type == DataType.Bip21:
            return str(self.data)
        if self.data_type == DataType.Descriptor:
            return self.data.as_string_private() if self.data else self.data
        if self.data_type == DataType.MultiPathDescriptor:
            return self.data.as_string_private() if self.data else self.data
        if self.data_type == DataType.SignerInfo:
            return str(self.data)
        if self.data_type == DataType.SignerInfos:
            return str(self.data)
        if self.data_type == DataType.PSBT:
            return str(self.data.serialize())
        if self.data_type == DataType.Tx:
            return str(serialized_to_hex(self.data.serialize()))
        if self.data_type == DataType.LabelsBip329:
            return str(self.data)

        return str(self.data)

    def __str__(self) -> str:
        return f"{self.data_type.name}: {self.data_as_string()}"

    @classmethod
    def _try_decode_bip21(cls, s, network: bdk.Network):
        try:
            return decode_bip21_uri(s, network=network)
        except Exception:
            pass

    @classmethod
    def _try_get_descriptor(cls, s, network: bdk.Network):
        try:
            assert "<" not in s, "This contains characters of a multipath descriptor"
            assert ">" not in s, "This contains characters of a multipath descriptor"
            descriptor = bdk.Descriptor(s, network)
            if descriptor:
                logger.debug("detected descriptor")
                return descriptor
        except Exception:
            pass

        try:
            specter_dict = json.loads(s)
            if "descriptor" in specter_dict:
                return cls._try_get_descriptor(specter_dict["descriptor"], network=network)
        except Exception:
            pass

    @classmethod
    def _try_get_multipath_descriptor(cls, s, network: bdk.Network):
        # if new lines are presnt, try checking if there are descriptors in the lines
        if "\n" in s:
            splitted_lines = s.split("\n")
            results = [cls._try_get_multipath_descriptor(line.strip(), network) for line in splitted_lines]
            # check that all entries return the same multipath descriptor
            # "None" entries are disallowed, to ensure that no depection is possible
            if all(results):
                all_identical = all(
                    element.as_string_private() == results[0].as_string_private() for element in results
                )
                if all_identical:
                    return results[0]
                else:
                    # the string contins multiple inconsitent descriptors.
                    # Don't know how to handle this properly.
                    raise InconsistentDescriptors(f"The descriptors {splitted_lines} are inconsistent.")
            else:
                # if splitting lines didnt work, then remove the \n and try to recognize all as 1 descriptor
                s = s.replace("\n", "")

        try:
            multipath_descriptor = MultipathDescriptor.from_descriptor_str(s, network)
            if multipath_descriptor:
                logger.debug("detected descriptor")
                return multipath_descriptor
        except Exception:
            pass

    @classmethod
    def _decoding_strategies(cls):
        return [
            lambda x: base64.b64decode(x),  # base64 decoding
            lambda x: bytes.fromhex(x),  # hex decoding
            lambda x: base43_decode(x),  # base43 decoding
            lambda x: base58.b58decode(x),
        ]

    @classmethod
    def _try_decode_psbt_binary(cls, raw: bytes):
        psbt_magic_bytes = b"psbt\xff"

        # Try each decoding strategy in the loop
        try:
            if raw[: len(psbt_magic_bytes)] == psbt_magic_bytes:
                return bdk.PartiallySignedTransaction(base64.b64encode(raw).decode())
        except Exception:
            return None
        return None

    @classmethod
    def _try_decode_psbt(cls, s):
        psbt_magic_bytes = b"psbt\xff"

        # Try each decoding strategy in the loop
        for decode in cls._decoding_strategies():
            try:
                decoded = decode(s)
                if decoded[:5] == psbt_magic_bytes:
                    return bdk.PartiallySignedTransaction(base64.b64encode(decoded).decode())
            except Exception:
                continue  # If one strategy fails, try the next

        return None

    @classmethod
    def _try_transaction_binary(cls, raw: bytes):
        # Try each decoding strategy in the loop
        try:
            return bdk.Transaction(raw)
        except Exception:
            return None

    @classmethod
    def _try_decode_serialized_transaction(cls, s: str):
        # Try each decoding strategy in the loop
        for decode in cls._decoding_strategies():
            try:
                decoded = decode(s)
                return bdk.Transaction(decoded)
            except Exception:
                continue  # If one strategy fails, try the next

        return None

    @classmethod
    def _try_extract_signer_info(cls, s, network: bdk.Network):
        signer_info = None
        try:
            signer_info = extract_signer_info(s)
        except:
            pass

        if signer_info:
            logger.debug("detected signer_info")
            if is_slip132(signer_info.xpub):
                signer_info.xpub = convert_slip132_to_bip32(signer_info.xpub)
            return signer_info

        # try to load from a generic json (and cobo)
        try:
            d = json.loads(s)
            fingerprint = None
            key_origin = None
            xpub = None
            if d.get("fingerprint"):
                fingerprint = d.get("fingerprint")
            if d.get("xfp"):
                fingerprint = d.get("xfp")
            if d.get("key_origin"):
                key_origin = d.get("key_origin")
            if d.get("deriv"):
                key_origin = d.get("deriv")
            if d.get("path"):
                # cobo convention
                key_origin = d.get("path")
            if d.get("xpub"):
                xpub = d.get("xpub")
            if fingerprint and key_origin and xpub:
                return SignerInfo(fingerprint=fingerprint, key_origin=key_origin, xpub=xpub)
        except Exception:
            pass

        return None

    @classmethod
    def _try_extract_sparrow_signer_infos(cls, s, network: bdk.Network):
        # if it is a json
        json_data = None
        try:
            json_data = json.loads(s)

            # check if it is in sparrow export format
            assert "chain" in json_data
            assert "xfp" in json_data
            assert "xpub" in json_data
        except:
            return None

        if network == bdk.Network.BITCOIN:
            if json_data["chain"] != "BTC":
                raise WrongNetwork(f"""Expected Network {network}, but got {json_data["chain"]}""")
        if network == bdk.Network.REGTEST:
            if json_data["chain"] != "XRT":
                raise WrongNetwork(f"""Expected Network {network}, but got {json_data["chain"]}""")
        if network == bdk.Network.TESTNET:
            if json_data["chain"] not in ["XTN", "TBTC"]:
                raise WrongNetwork(f"""Expected Network {network}, but got {json_data["chain"]}""")
        if network == bdk.Network.SIGNET:
            # unclear which chain value is used for signet in coldcard
            # https://coldcard.com/docs/upgrade/#mk4-version-511-feb-27-2023
            if json_data["chain"] not in ["XTN", "XRT"]:
                raise WrongNetwork(f"""Expected Network {network}, but got {json_data["chain"]}""")

        # the fingerprint in the top level is the relevant one
        fingerprint = json_data["xfp"]

        return [
            SignerInfo(
                xpub=v["xpub"],
                fingerprint=fingerprint,
                key_origin=v["deriv"],
                first_address=v["first"] if "first" in v else None,
                name=v["name"],
            )
            for k, v in json_data.items()
            if k.lower().startswith("bip")
        ]

    @classmethod
    def _try_extract_multisig_signer_infos_coldcard_and_passport_qr(cls, s, network: bdk.Network):
        # if it is a json
        json_data = None
        try:
            json_data = json.loads(s)

            # check if it is in coldcard export format
            assert "xfp" in json_data
            # for coldcard  assert "account" in json_data
            # for passport  assert "account" not in json_data

        except Exception:
            return None

        # the fingerprint in the top level is the relevant one
        fingerprint = json_data["xfp"]

        # get all the main keys (address type names) by looking at which end with _deriv
        address_type_names = [key.rstrip("_deriv") for key in json_data if key.endswith("_deriv")]

        signer_infos = [
            SignerInfo(
                xpub=convert_slip132_to_bip32(json_data[address_type_name])
                if is_slip132(json_data[address_type_name])
                else json_data[address_type_name],
                fingerprint=fingerprint,
                key_origin=json_data[address_type_name + "_deriv"],
                name=address_type_name,
            )
            for address_type_name in address_type_names
        ]
        for signer_info in signer_infos:
            cls.ensure_xpub_matches_network(signer_info.xpub, network=network)
        return signer_infos

    @classmethod
    def ensure_xpub_matches_network(cls, xpub: str, network: bdk.Network):
        if network == bdk.Network.BITCOIN:
            if not xpub.startswith("xpub"):
                raise WrongNetwork(f"{xpub} doesnt start with xpub, which is required for {network}")
        else:
            if not xpub.startswith("tpub"):
                raise WrongNetwork(f"{xpub} doesnt start with tpub, which is required for {network}")

    @classmethod
    def _try_jade_wallet_export_to_signer_infos(
        cls, s: str, network: bdk.Network
    ) -> Optional[List[SignerInfo]]:
        def convert_to_signer_infos(data: str) -> List[SignerInfo]:
            # Initialize variables
            lines = data.strip().split("\n")
            # wallet_info = {}
            signer_infos: List[SignerInfo] = []
            key_origin = None

            # # Iterate through each line
            # for line in lines:
            #     if line.startswith("# Exported by"):
            #         wallet_info["Exported_by"] = line.split(" by ")[-1]
            #     elif line.startswith("Name:"):
            #         wallet_info["Name"] = line.split(": ")[-1]
            #     elif line.startswith("Policy:"):
            #         wallet_info["Policy"] = line.split(": ")[-1]
            #     elif line.startswith("Format:"):
            #         wallet_info["Format"] = line.split(": ")[-1]

            for line_key_origin, line_xpub_fingeprint in zip(lines, lines[1:]):
                if line_key_origin.startswith("Derivation:"):
                    key_origin = line_key_origin.split(":")[-1].strip()
                    if not key_origin.startswith("m/"):
                        continue

                    fingerprint, xpub = line_xpub_fingeprint.split(":")
                    fingerprint = fingerprint.strip()
                    xpub = xpub.strip()
                    if len(fingerprint) != 8:
                        continue

                    signer_infos.append(SignerInfo(fingerprint=fingerprint, key_origin=key_origin, xpub=xpub))

            for signer_info in signer_infos:
                cls.ensure_xpub_matches_network(signer_info.xpub, network=network)
            return signer_infos

        try:
            # Decode the hex string to ASCII
            decoded_text = binascii.unhexlify(s).decode("utf-8")

            # the data now looks like
            # "# Exported by Blockstream Jade
            # Name: hwi3374c2e55c4b
            # Policy: 2 of 3
            # Format: P2WSH
            # Derivation: m/48'/1'/0'/2'
            # 14c949b4: tpubDDvtDSGt5JmgxgpRp3nyZj3ULZvFWuU9AaS6x3UwkNE6vaNgzd6oyKYEQUzSevUQs2ste5QznpbN8Nt5bVbZvrJFpCqw9UPXCtnCutEvEwW
            # Derivation: m/48'/1'/0'/2'
            # d8cf7475: tpubDEDUiUcwmoC92QJ2kGPQwtikGqLrjdyUfuRMhm5ab4nYmgRkkKPF9mp2FcunzMu9y5Ea2urGUJh4t1o7Wb6KjKddzJKcE8BoAyTWK6ughFK
            # Derivation: m/48'/1'/0'/2'
            # d5b43540: tpubDFnCcKU3iUF4sPeQC68r2ewDaBB7TvLmQBTs12hnNS8nu6CPjZPmzapp7Woz6bkFuLfSjSpg6gacheKBaWBhDnEbEpKtCnVFdQnfhYGkPQF"
            return convert_to_signer_infos(decoded_text)
        except:
            pass
        return None

    @classmethod
    def from_binary(cls, raw: bytes, network: bdk.Network) -> "Data":
        # # Sequence of checks to identify the type of data in `s`
        # if decoded_bip21 := cls._try_decode_bip21(s, network=network):
        #     return Data(decoded_bip21, DataType.Bip21)

        # if is_xpub(s):
        #     data = convert_slip132_to_bip32(s) if is_slip132(s) else s
        #     return Data(data, DataType.Xpub)

        # if descriptor := cls._try_get_descriptor(s, network):
        #     return Data(descriptor, DataType.Descriptor)

        # if descriptor := cls._try_get_multipath_descriptor(s, network):
        #     return Data(descriptor, DataType.MultiPathDescriptor)

        # if is_valid_bitcoin_hash(s):
        #     return Data(s, DataType.Txid)

        # if is_valid_wallet_fingerprint(s):
        #     return Data(s, DataType.Fingerprint)

        if psbt := cls._try_decode_psbt_binary(raw):
            return Data(psbt, DataType.PSBT)

        if tx := cls._try_transaction_binary(raw):
            return Data(tx, DataType.Tx)

        # if signer_info := cls._try_extract_signer_info(s, network):
        #     return Data(signer_info, DataType.SignerInfo)

        # if signer_infos := cls._try_extract_signer_infos(s, network):
        #     return Data(signer_infos, DataType.SignerInfos)

        # if is_bip329(s):
        #     return Data(s, DataType.LabelsBip329)

        raise DecodingException(f"{raw} Could not be decoded with from_binary")  # type: ignore

    @classmethod
    def from_tx(cls, tx: bdk.Transaction) -> "Data":
        assert isinstance(tx, bdk.Transaction)
        return Data(tx, DataType.Tx)

    @classmethod
    def from_psbt(cls, psbt: bdk.PartiallySignedTransaction) -> "Data":
        assert isinstance(psbt, bdk.PartiallySignedTransaction)
        return Data(psbt, DataType.PSBT)

    @classmethod
    def from_descriptor(cls, descriptor: bdk.Descriptor) -> "Data":
        assert isinstance(descriptor, bdk.Descriptor)
        return Data(descriptor, DataType.Descriptor)

    @classmethod
    def from_multipath_descriptor(cls, multipath_descriptor: MultipathDescriptor) -> "Data":
        assert isinstance(multipath_descriptor, MultipathDescriptor)
        return Data(multipath_descriptor, DataType.MultiPathDescriptor)

    @classmethod
    def from_str(cls, s: str, network: bdk.Network) -> "Data":
        s = s.strip()
        data = None

        # Sequence of checks to identify the type of data in `s`
        if decoded_bip21 := cls._try_decode_bip21(s, network=network):
            return Data(decoded_bip21, DataType.Bip21)

        if is_xpub(s):
            data = convert_slip132_to_bip32(s) if is_slip132(s) else s
            return Data(data, DataType.Xpub)

        if descriptor := cls._try_get_descriptor(s, network):
            return Data(descriptor, DataType.Descriptor)

        if descriptor := cls._try_get_multipath_descriptor(s, network):
            return Data(descriptor, DataType.MultiPathDescriptor)

        if is_valid_bitcoin_hash(s):
            return Data(s, DataType.Txid)

        if is_valid_wallet_fingerprint(s):
            return Data(s, DataType.Fingerprint)

        if psbt := cls._try_decode_psbt(s):
            return Data(psbt, DataType.PSBT)

        if tx := cls._try_decode_serialized_transaction(s):
            return Data(tx, DataType.Tx)

        if signer_info := cls._try_extract_signer_info(s, network):
            return Data(signer_info, DataType.SignerInfo)

        if signer_infos := cls._try_extract_sparrow_signer_infos(s, network):
            return Data(signer_infos, DataType.SignerInfos)

        if signer_infos := cls._try_extract_multisig_signer_infos_coldcard_and_passport_qr(s, network):
            return Data(signer_infos, DataType.SignerInfos)

        if is_bip329(s):
            return Data(s, DataType.LabelsBip329)

        if signer_infos := cls._try_jade_wallet_export_to_signer_infos(s, network=network):
            return Data(signer_infos, DataType.SignerInfos)

        raise DecodingException(f"{s} Could not be decoded with from_str")

    def write_to_filedescriptor(self, fd):
        """

        This is useful for a temporary file
        fd, file_path = tempfile.mkstemp(
            suffix=f"_{key}.{self.file_extension}", prefix=""
        )

        a file descriptor for a normal file can be created with
                fd = os.open(filename, os.O_CREAT | os.O_WRONLY)
        """
        if self.data_type == DataType.Tx:
            with fdopen(fd, "wb") as file:
                file.write(bytes(self.data.serialize()))
        elif self.data_type == DataType.PSBT:
            with fdopen(fd, "wb") as file:
                file.write(base64.b64decode(self.data.serialize()))
        else:
            with fdopen(fd, "w") as file:
                file.write(self.data_as_string())
